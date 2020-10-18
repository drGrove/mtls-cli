"""mtls (Mutual TLS) - A cli for creating short-lived client certiicates."""

import binascii
import os
import pkg_resources
import platform
import random
import subprocess
import sys
from configparser import ConfigParser
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import OpenSSL
import click
import gnupg
import json
import requests


class GPGDecryptionException(Exception):
    pass


class MutualTLS:
    MISSING_CONFIGURATION = """
    Configuration missing for mtls at {}/{}
    """
    MISSING_CONFIGURATION_FOR_SERVER = """
    Configuration missing for server: {server}

    Please ensure that you have a configuration for you server similar to:
    [{server}]
    email=foo@example.com
    url=https://ca.example.com

    For more details see config.ini.example
    """

    def __init__(self, server, options={}):
        self.HOME = os.environ.get("HOME")
        self.GNUPGHOME = os.environ.get("GNUPGHOME")
        self.USER = os.environ.get("USER")
        self.options = options
        self.override = False
        if options["config"] is None:
            self.CONFIG_FOLDER_PATH = f"{self.HOME}/.config/mtls"
            self.CONFIG_FILE = "config.ini"
            self.config_file_path = (
                f"{self.CONFIG_FOLDER_PATH}/{self.CONFIG_FILE}"
            )
        else:
            self.CONFIG_FOLDER_PATH = "/".join(
                options["config"].split("/")[:-1]
            )
            self.CONFIG_FILE = options["config"].split("/")[-1]
            self.config_file_path = options["config"]
        self.USER_KEY = f"{self.USER}.key.gpg"
        self.GNUPGHOME = os.environ.get("GNUPGHOME")
        if self.GNUPGHOME is None:
            self.GNUPGHOME = "{}/{}".format(os.environ.get("HOME"), ".gnupg")
        self.gpg = gnupg.GPG(gnupghome=self.GNUPGHOME)
        self.gpg.encoding = "utf-8"
        self.config = self.get_config()
        self.server = server
        self._make_server_dir_if_missing()
        self.server_in_config()
        self.openssl_format = serialization.PrivateFormat.TraditionalOpenSSL
        self.no_encyption = serialization.NoEncryption()
        self.friendly_name = "{org} - {user}@{hostname}".format(
            org=self.config.get(self.server, "organization_name"),
            user=str(os.environ.get("USER")),
            hostname=str(platform.uname()[1]),
        )
        self.BASE_SERVER_PATH = f"{self.CONFIG_FOLDER_PATH}/{self.server}"
        self.pfx_path = f"{self.BASE_SERVER_PATH}/{self.server}.pfx"
        self.cert_file_path = f"{self.BASE_SERVER_PATH}/{self.server}.pem"
        self.ca_cert_file_path = (
            f"{self.BASE_SERVER_PATH}/{self.server}_Root_CA.pem"
        )
        self.crl_file_path = f"{self.BASE_SERVER_PATH}/crl.pem"

    def check_revoked(self, cert):
        with open(self.crl_file_path, "rb") as f:
            crl = x509.load_pem_x509_crl(
                data=f.read(), backend=default_backend()
            )
            if cert.issuer != crl.issuer:
                click.secho("Cert does not match CRL", fg="red")
                sys.exit(1)
            for revoked in crl:
                if cert.serial == revoked.serial_number:
                    return True

            return False

    def create_cert(self, output):
        if output:
            self.override = True
        self._create_db()
        cert = None
        if not self._has_root_cert():
            self._get_and_set_root_cert()
        if sys.platform == "darwin":
            (valid, exists, revoked) = self.check_valid_cert(
                name=self.cert_file_path
            )
        else:
            (valid, exists, revoked) = self.check_valid_cert(
                name=self.friendly_name
            )
        if valid is True:
            click.secho("Reusing valid certificate", fg="green")
            sys.exit(0)
        if valid is False and exists is True:
            if sys.platform == "darwin":
                self.delete_cert_by_name(self.friendly_name)
            else:
                self.delete_cert_by_name(self.friendly_name)
        if valid is False and revoked is False and exists is True:
            cert = self.get_cert_from_file()
        csr = self.get_csr()
        key = self.get_key_or_generate()
        if csr is None:
            csr = self.generate_csr(key)
        else:
            click.secho(
                f"Reusing previously generated CSR for {self.server}",
                fg="green",
            )
        cert_str = self.sign_and_send_to_server(csr)
        if cert_str is None:
            click.echo("Could not retrieve certificate from server")
            sys.exit(1)
        cert = self.convert_to_cert(cert_str)
        try:
            with open(self.cert_file_path, "w") as cert_file:
                click.echo("Writing file to {}".format(self.cert_file_path))
                cert_file.write(
                    cert.public_bytes(serialization.Encoding.PEM).decode(
                        "utf-8"
                    )
                )
        except Exception as e:
            click.secho(
                "Could not write certificate to {}".format(
                    self.cert_file_path
                ),
                fg="red",
            )
        if cert is None:
            click.echo("Could not convert to certificate")
            sys.exit(1)
        p12 = OpenSSL.crypto.PKCS12()
        pkey = OpenSSL.crypto.PKey.from_cryptography_key(key)
        fpbytes = cert.fingerprint(hashes.SHA1())
        fp = binascii.hexlify(fpbytes)
        if not self.override:
            self.update_config_value(
                "current_sha", fp.decode("UTF-8"), self.server
            )
        certificate = OpenSSL.crypto.X509.from_cryptography(cert)
        p12.set_privatekey(pkey)
        p12.set_certificate(certificate)
        p12.set_friendlyname(bytes(self.friendly_name, "UTF-8"))
        pwd = self._genPW()
        if output:
            self.pfx_path = output
            pw = self.encrypt(pwd, self.config.get(self.server, "fingerprint"))
            pfx_base = "/".join(self.pfx_path.split("/")[:-1])
            pw_file = self.pfx_path.split("/")[-1].split(".")[:-1]
            pw_file += ".password.asc"
            pw_file = "".join(pw_file)
            pw_file = "{}/{}".format(pfx_base, pw_file)
            with open(pw_file, "wb") as pwfile:
                click.echo("Writing password to: {}".format(pw_file))
                pwfile.write(str(pw).encode("UTF-8"))
        with open(self.pfx_path, "wb") as f:
            f.write(p12.export(passphrase=bytes(pwd, "UTF-8")))
        if not output:
            self.update_cert_storage(self.pfx_path, pwd)
            self._chrome_notice()
            self._firefox_notice()

    def _chrome_notice(self):
        CHROME_NOTICE = (
            "If using Chrome/Chromium you may have to restart before these "
            + "certificates take effect. chrome://restart"
        )
        click.secho(CHROME_NOTICE, fg="green")

    def _firefox_notice(self):
        click.secho(
            "If using Firefox you may have to restart "
            + "before these certificates take effect. about:profiles",
            fg="green",
        )

    def _has_root_cert(self):
        if sys.platform == "darwin":
            name = self.ca_cert_file_path
        else:
            name = "{server} Root CA".format(server=self.server)
        if self.check_valid_cert(name, usage="CT,T,T", is_root=True):
            return True
        return False

    def _get_and_set_root_cert(self):
        response = self.send_request(
            server_url="{url}/ca".format(
                url=self.config.get(self.server, "url")
            ),
            method="get",
        )
        try:
            data = response.json()
        except Exception:
            click.secho(
                "Error parsing Root Certificate from server.", fg="red"
            )
            sys.exit(1)
        # Update the issuer name directly from the server into your config
        self.config.set(self.server, "issuer", data["issuer"])
        self.update_config()
        # Write the file to the CA Cert File path so that it's accessible to
        # the user and subsequent calls later.
        with open(self.ca_cert_file_path, "w") as ca_cert:
            ca_cert.write(data["cert"])
        self.add_root_ca_to_store(self.ca_cert_file_path)

    def add_root_ca_to_store(self, ca_cert_file_path):
        click.echo("Adding root certificate to certificate store...")
        paths = self._get_certdb_paths()
        if sys.platform == "darwin":
            cmds = []
            add_trust_keychain = [
                "security",
                "add-trusted-cert",
                "-p",
                "ssl",
                "-r",
                "trustAsRoot",
                ca_cert_file_path,
            ]
            import_keychain = ["security", "import", ca_cert_file_path]
            cmds = [add_trust_keychain, import_keychain]
            for cmd in cmds:
                try:
                    self._run_cmd(cmd, capture_output=True)
                except Exception as e:
                    click.echo("Error")
                    click.echo(e)
            # Override paths for darwin to only handle firefox
            paths = self._firefox_certdb_location()
        if sys.platform == "linux" or sys.platform == "linux2" or "darwin":
            for path in paths:
                cmd = [
                    "certutil",
                    "-A",
                    "-d",
                    path,
                    "-t",
                    "CT,CT,CT",
                    "-i",
                    ca_cert_file_path,
                    "-n",
                    "{server} Root CA".format(server=self.server),
                ]
                try:
                    self._run_cmd(cmd, capture_output=True)
                except Exception as e:
                    click.echo("Error")
                    click.echo(e)

    def delete_cert_by_name(self, name):
        paths = self._get_certdb_paths()
        if sys.platform == "darwin":
            fingerprint = self.config.get(
                self.server, "current_sha", fallback=""
            )
            if fingerprint != "":
                click.secho(
                    "Deleting invalid/expired certificates for {}".format(
                        fingerprint
                    ),
                    fg="yellow",
                )
                delete_identity_cmd = [
                    "security",
                    "delete-identity",
                    "-Z",
                    fingerprint,
                ]
                output = self._run_cmd(
                    delete_identity_cmd, capture_output=True
                )
            # Override path to just be firefox on darwin for the next command
            paths = self._firefox_certdb_location()
        if sys.platform in ["linux", "linux2", "darwin"]:
            click.secho(
                "Deleting invalid/expired certificates for {}".format(name),
                fg="yellow",
            )
            for path in paths:
                cmd = ["certutil", "-D", "-d", path, "-n", name]

                try:
                    output = self._run_cmd(cmd, capture_output=True)
                except Exception as e:
                    click.echo(
                        "Error deleting certificate with name: {}".format(name)
                    )
                    click.echo(e)

    def check_valid_cert(self, name=None, usage="V", is_root=False):
        if name is None:
            click.echo("A valid certificate name is required")
            sys.exit(1)
        paths = self._get_certdb_paths()
        is_valid = False
        revoked = False
        cert_exists = os.path.isfile(self.cert_file_path)
        if not cert_exists:
            return is_valid, cert_exists, revoked
        if self.config.get(self.server, "issuer", fallback=None) is None:
            # If the config doesn't have an issuer, we can by default know that
            # a user has not received this information from the server or set
            # it themselves and can assume they don't have a certificate yet
            return False
        if sys.platform == "darwin":
            # Name is the path to the certificate file, because
            # security does not support verification once a certificate is
            # installed, so we must check that:
            # a) the certificate file exist
            # b) is it actually valid
            # We are only checking Keychain as we cannot verify that Firefox is
            # actually installed and we should not be making that assumption.
            if is_root:
                cmd = [
                    "security",
                    "find-certificate",
                    "-c",
                    self.config.get(self.server, "issuer"),
                ]
                find_cert_output = self._run_cmd(cmd, capture_output=True)
                if "The specified item could not be found" in str(
                    find_cert_output.stderr, "UTF-8"
                ):
                    return is_valid, cert_exists, revoked
                cmd = ["security", "verify-cert", "-r", self.ca_cert_file_path]
            else:
                find_cert_output = self._run_cmd(
                    ["security", "find-identity", "-p", "ssl-client", "-v"],
                    capture_output=True,
                )
                stdout_str = find_cert_output.stdout.decode("UTF-8")
                if self.friendly_name not in stdout_str:
                    return is_valid, cert_exists, revoked
                if "The specified item could not be found" in str(
                    find_cert_output.stderr, "UTF-8"
                ):
                    return is_valid, cert_exists, revoked
                cmd = [
                    "security",
                    "verify-cert",
                    "-c",
                    name,
                    "-r",
                    self.ca_cert_file_path,
                ]

            output = self._run_cmd(cmd, capture_output=True)
            if "CSSMERR_TP_NOT_TRUSTED" in output.stdout.decode("UTF-8"):
                is_valid = False
            if "CSSMERR_TP_CERT_EXPIRED" in output.stderr.decode("UTF-8"):
                is_valid = False
        elif sys.platform == "linux" or sys.platform == "linux2":
            for path in paths:
                cmd = [
                    "certutil",
                    "-V",
                    "-u",
                    usage,
                    "-d",
                    path,
                    "-n",
                    "{name}".format(name=name),
                ]
                output = self._run_cmd(cmd, capture_output=True)
                if "could not find certificate" in str(output.stderr, "UTF-8"):
                    # No certificate found so it's not valid, exists or revoked
                    is_valid = False
                    revoked = False
                if "certificate is invalid" in str(output.stdout, "UTF-8"):
                    is_valid = False
                    revoked = self.check_revoked(self.get_cert_from_file())
                if "validation failed" in str(output.stderr, "UTF-8"):
                    is_valid = False
                    revoked = self.check_revoked(self.get_cert_from_file())
        return is_valid, cert_exists, revoked

    def get_cert_from_file(self):
        with open(self.cert_file_path, "rb") as cert_file:
            return x509.load_pem_x509_certificate(
                cert_file.read(), default_backend()
            )

    def decrypt(self, data, is_file=True):
        if is_file:
            data = self.gpg.decrypt_file(data)
        else:
            data = self.gpg.decrypt(data)

        if data.ok is False:
            raise GPGDecryptionException(data.status)

        return str(data)

    def get_csr(self):
        csr_path = "{}/{}.csr.asc".format(self.CONFIG_FOLDER_PATH, self.server)
        if not os.path.isfile(csr_path) or self.override:
            return None
        click.echo("Decrypting CSR...")
        try:
            csr_str = self.decrypt(open(csr_path, "rb"))
        except GPGDecryptionException:
            click.secho("Failed to decrypt CSR, invalid password.", fg="red")
            sys.exit(1)
        return x509.load_pem_x509_csr(
            bytes(csr_str, "utf-8"), default_backend()
        )

    def _genPW(self):
        wordList = []
        with pkg_resources.resource_stream(
            __name__, "share/password_word_list"
        ) as wordFile:
            for line in wordFile:
                wordList.append(line.decode().rstrip("\n"))
        pw = []
        for c in range(10):
            pw.append(random.choice(wordList))
        return " ".join(pw).rstrip()

    def convert_to_cert(self, cert):
        try:
            cert = bytes(str(cert), "utf-8")
            cert = x509.load_pem_x509_certificate(
                cert, backend=default_backend()
            )
            return cert
        except Exception as e:
            click.secho(
                "Failure to load PEM x509 Certificate: {}".format(e),
                fg="red",
                err=True,
            )

    def _run_cmd(self, args, capture_output=False):
        if capture_output:
            return subprocess.run(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        return subprocess.run(args)

    def update_cert_storage(self, cert_file_path, cert_pw):
        if sys.platform == "linux" or sys.platform == "linux2":
            paths = self._get_certdb_paths()
            for path in paths:
                try:
                    cmd = [
                        "pk12util",
                        "-i",
                        cert_file_path,
                        "-d",
                        path,
                        "-W",
                        cert_pw,
                        "-n",
                        str(platform.uname()[1]),
                    ]
                    output = self._run_cmd(cmd, capture_output=True)
                    if "SEC_ERROR_REUSED_ISSUER_AND_SERIAL" in str(
                        output.stderr, "UTF-8"
                    ):
                        self.delete_cert_by_name(self.friendly_name)
                        self.update_cert_storage(cert_file_path, cert_pw)
                        return
                except Exception as e:
                    cse = "Could not add certificate to certificate store"
                    click.secho(cse, fg="red", err=True)
                    click.echo(e)
        elif sys.platform == "darwin":
            try:
                # Add to keychain
                self._run_cmd(
                    [
                        "security",
                        "import",
                        cert_file_path,
                        "-f",
                        "pkcs12",
                        "-x",
                        "-P",
                        cert_pw,
                    ],
                    capture_output=True,
                )
            except Exception as e:
                click.echo("Could not add certificate to certificate store")
            try:
                # Add to FireFox Store
                paths = self._firefox_certdb_location()
                for path in paths:
                    cmd = [
                        "pk12util",
                        "-i",
                        cert_file_path,
                        "-d",
                        path,
                        "-W",
                        cert_pw,
                        "-n",
                        str(platform.uname()[1]),
                    ]
                    self._run_cmd(cmd, capture_output=True)
            except Exception as e:
                click.secho(
                    "Could not add certificate to certificate store",
                    fg="red",
                    err=True,
                )
                click.echo(e)
        else:
            try:
                self._run_cmd(
                    ["certutil.exe", "-viewstore", "-user", "root"],
                    capture_output=True,
                )
            except Exception as e:
                click.echo("Could not add certificate to certificate store")
                click.echo(e)

    def _make_server_dir_if_missing(self):
        path = "{config}/{server}".format(
            config=self.CONFIG_FOLDER_PATH, server=self.server
        )
        if not os.path.isdir(path):
            os.makedirs(path)

    def _create_db(self):
        path = self._primary_certdb_location()
        if sys.platform == "linux" or sys.platform == "linux2":
            if not os.path.isdir(path):
                os.makedirs(path)
                # This assumes that you're using an encrypted hard drive
                # Othewise we need to look into a way to allow user input
                # Probably swapping subprocess.call with subprocess.popen so
                # that users can manually enter passwords
                click.secho("Making nssdb at {}".format(path), fg="green")
                subprocess.call(
                    ["certutil", "-d", path, "-N", "--empty-password"]
                )

    def _get_certdb_paths(self):
        paths = (
            [self._primary_certdb_location()]
            + self._firefox_certdb_location()
            + self._chrome_certdb_location()
        )
        return paths

    def _primary_certdb_location(self):
        return os.path.join(self.HOME, ".pki/nssdb")

    def _chrome_certdb_location(self):
        if sys.platform == "linux" or sys.platform == "linux2":
            if os.path.isdir(os.path.join(self.HOME, "snap")):
                return [
                    os.path.join(self.HOME, "snap/chromium/current/.pki/nssdb")
                ]

        return []

    def _firefox_certdb_location(self):
        base_path = None
        paths = []
        if sys.platform == "linux" or sys.platform == "linux2":
            base_path = os.path.join(self.HOME, ".mozilla/firefox")

        elif sys.platform == "darwin":
            # Make directory if it doesn't exist
            base_path = os.path.join(
                self.HOME, "Library/Application Support/Firefox/Profiles/"
            )
        elif sys.platform == "win32":
            base_path = os.path.join(
                os.getenv("USERPROFILE"), "\\AppData\\Local\\Firefox"
            )
        if base_path is not None:
            posix_paths = list(Path(base_path).rglob("cert*.db"))
            for pp in posix_paths:
                paths.append("/".join(str(pp).split("/")[:-1]))
        return paths

    def check_for_config(self):
        """Check if the config exists, otherwise exit."""
        config_dir_exists = os.path.isdir(self.CONFIG_FOLDER_PATH)
        config_exists = os.path.isfile(self.config_file_path)

        if not config_dir_exists or not config_exists:
            msg = self.MISSING_CONFIGURATION.format(
                self.CONFIG_FOLDER_PATH, self.CONFIG_FILE
            )
            click.echo(msg)
            sys.exit(1)

    def get_config(self):
        """Gets config from file.

        Returns:
            config
        """
        self.check_for_config()
        config = ConfigParser()
        config.read(self.config_file_path)
        return config

    def update_config_value(self, key, value, namespace="DEFAULT"):
        self.config.set(namespace, key, value)
        self.update_config(show_msg=False)

    def update_config(self, show_msg=True):
        if show_msg:
            click.secho(
                "Updating config file settings for {server}".format(
                    server=self.server
                ),
                fg="green",
            )
        with open(self.config_file_path, "w") as config_file:
            self.config.write(config_file)

    def server_in_config(self):
        """Determines if the set server is in the config, otherwise exit."""
        if self.server is None and len(self.config.sections()) > 1:
            click.echo(
                "You have multiple servers configured, please "
                + "selection one with the --server (-s) option"
            )
        if self.server not in self.config:
            click.echo(
                self.MISSING_CONFIGURATION_FOR_SERVER.format(
                    server=self.server
                )
            )
            sys.exit(1)

    def encrypt(self, data, recipient, sign=False):
        """Encrypt data using PGP to recipient."""
        if sign is True:
            click.echo("Encrypting and Signing data...")
        return self.gpg.encrypt(data, recipient, sign=sign)

    def get_key_or_generate(self):
        """Get users key from file or generate a new RSA Key.

        Returns:
            key - RSA Key
        """
        key = None
        key_path = "{config_folder}/{user_key}".format(
            config_folder=self.CONFIG_FOLDER_PATH, user_key=self.USER_KEY
        )
        if os.path.isfile(key_path):
            click.echo("Decrypting User Key...")
            try:
                key_data = self.decrypt(open(key_path, "rb"))
            except GPGDecryptionException:
                click.secho(
                    "Failed to decrypt user key. Invalid password", fg="red"
                )
                sys.exit(1)
            byte_key_data = bytes(str(key_data), "utf-8")
            key = serialization.load_pem_private_key(
                byte_key_data, password=None, backend=default_backend()
            )
        else:
            click.echo("Generating User Key")
            key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )
            key_data = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=self.openssl_format,
                encryption_algorithm=self.no_encyption,
            )
            user_fingerprint = self.config.get(self.server, "fingerprint")
            encrypted_key = self.encrypt(key_data, user_fingerprint)
            user_email = self.config.get(self.server, "email")
            click.echo("Encrypting file to {}".format(user_email))
            with open(key_path, "w") as f:
                f.write(str(encrypted_key))
        return key

    def generate_csr(self, key):
        """Generates a CSR.

        Args:
            key - The users key

        Returns:
            csr - The CSR
        """
        click.secho(
            "Generating CSR for {server}".format(server=self.server),
            fg="yellow",
        )
        country = self.config.get(self.server, "country", fallback=None)
        state = self.config.get(self.server, "state", fallback=None)
        locality = self.config.get(self.server, "locality", fallback=None)
        organization_name = self.config.get(self.server, "organization_name")
        email = self.config.get(self.server, "email")
        csr_subject_arr = [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, self.friendly_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ]
        if state:
            csr_subject_arr.append(
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state)
            )
        if country:
            csr_subject_arr.append(
                x509.NameAttribute(NameOID.COUNTRY_NAME, country)
            )
        if locality:
            csr_subject_arr.append(
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality)
            )
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name(csr_subject_arr))
            .sign(key, hashes.SHA256(), default_backend())
        )
        csr_fname = "{}.csr.asc".format(self.server)

        # If the user overrides the ini configuration programatically, don't
        # save the CSR as this could be a one off.
        if self.override:
            return csr

        with open(
            "{config}/{server}/{csr}".format(
                config=self.CONFIG_FOLDER_PATH,
                server=self.server,
                csr=csr_fname,
            ),
            "wb",
        ) as f:
            enc_csr = self.encrypt(
                csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                self.config.get(self.server, "fingerprint"),
            )
            f.write(bytes(str(enc_csr), "utf-8"))
        return csr

    def _get_path(self, path):
        """Gets the absolute path given a path."""
        if not os.path.isabs(path):
            return os.path.abspath(os.path.join(self.CONFIG_FOLDER_PATH, path))

    def send_request(self, payload=None, method="post", server_url=None):
        if server_url is None:
            server_url = self.config.get(self.server, "url")
        if method == "post":
            if payload is None:
                click.secho(
                    "Payload missing for request. Cancelling",
                    fg="red",
                    err=True,
                )
            return requests.post(server_url, json=payload, verify=True)
        if method == "delete":
            if payload is None:
                click.secho(
                    "Payload missing for request. Cancelling",
                    fg="red",
                    err=True,
                )
            return requests.delete(server_url, json=payload, verify=True)
        if method == "get":
            return requests.get(server_url, verify=True)
        click.secho(
            "Failed to properly send request to server, "
            + "invalid method passed to MutualTLS.send_request"
        )
        sys.exit(1)

    def gen_sig(self, data, echo_msg):
        click.echo(echo_msg)
        if self.options["gpg_password"]:
            return self.gpg.sign(
                data,
                keyid=self.config.get(self.server, "fingerprint"),
                passphrase=self.options["gpg_password"],
                detach=True,
                clearsign=True,
            )
        else:
            return self.gpg.sign(
                data,
                keyid=self.config.get(self.server, "fingerprint"),
                detach=True,
                clearsign=True,
            )

    def sign_and_send_to_server(self, csr):
        """Sign and send to server.

        Args:
            csr - The CSR

        Returns:
            cert - the certificate
        """
        csr_public_bytes = csr.public_bytes(serialization.Encoding.PEM)
        msg = "Signing CSR for verification on server..."
        signature = self.gen_sig(csr_public_bytes, msg)
        payload = {
            "csr": csr_public_bytes.decode("utf-8"),
            "signature": str(signature),
            "lifetime": self.config.get(
                self.server, "lifetime", fallback=64800
            ),
            "type": "CERTIFICATE",
        }
        response = self.send_request(payload)
        try:
            response = response.json()
        except Exception as e:
            click.secho(
                "Error handling response from server. Bailing", fg="red"
            )
            sys.exit(-1)
        if response.get("error", False):
            click.echo(response.get("msg"))
            sys.exit(1)
        return str(response["cert"])

    def revoke_cert(self, fingerprint, serial_number, common_name):
        payload = {"query": {}, "type": "CERTIFICATE"}
        if fingerprint is not None:
            payload["query"]["fingerprint"] = fingerprint
        if serial_number is not None:
            payload["query"]["serial_number"] = serial_number
        if common_name is not None:
            payload["query"]["common_name"] = common_name
        msg = "Signing Revoke Request..."
        payload["signature"] = str(
            self.gen_sig(json.dumps(payload["query"]).encode("UTF-8"), msg)
        )
        response = self.send_request(payload, method="delete")
        response = response.json()
        if response.get("error", False):
            click.echo(response.get("msg"))
            sys.exit(1)
        click.echo("Certificate Revoked")

    def add_user(self, fingerprint, is_admin=False):
        msg = "Signing Add User Request..."
        payload = {
            "type": "ADMIN" if is_admin else "USER",
            "fingerprint": fingerprint,
            "signature": str(self.gen_sig(fingerprint.encode("UTF-8"), msg)),
        }
        response = self.send_request(payload, method="post")
        response = response.json()
        if response.get("error", False):
            click.echo(response.get("msg"))
            sys.exit(1)
        if is_admin:
            _type = "Admin"
        else:
            _type = "User"
        click.secho(
            "Added {_type}: {fingerprint}".format(
                fingerprint=fingerprint, _type=_type
            ),
            fg="green",
        )

    def remove_user(self, fingerprint, is_admin=False):
        msg = "Signing Remove User Request..."
        payload = {
            "type": "ADMIN" if is_admin else "USER",
            "fingerprint": fingerprint,
            "signature": str(self.gen_sig(fingerprint.encode("UTF-8"), msg)),
        }
        response = self.send_request(payload, method="post")
        response = response.json()
        if response.get("error", False):
            click.echo(response.get("msg"))
            sys.exit(1)
        if is_admin:
            _type = "Admin"
        else:
            _type = "User"
        click.secho(
            "Removed {_type}: {fingerprint}".format(
                fingerprint=fingerprint, _type=_type
            ),
            fg="green",
        )

    def set_user_options(self, options):
        for key in options:
            self.config.set(self.server, key, options.get(key))

        if options.get("common_name"):
            self.friendly_name = "{org} - {name}".format(
                org=self.config.get(self.server, "organization_name"),
                name=options["common_name"],
            )

        if options.get("friendly_name"):
            self.friendly_name = "{org} - {name}".format(
                org=self.config.get(self.server, "organization_name"),
                name=options["friendly_name"],
            )

    def get_crl(self, output):
        if not output:
            click.echo("Retrieving CRL from server...")
        response = self.send_request(
            server_url=self.config.get(self.server, "url") + "/crl",
            method="get",
        )
        if response.status_code != 200:
            click.secho(
                "Failed to retrieve CRL from {}".format(self.server),
                fg="red",
                err=True,
            )
        if output:
            click.echo(response.text)
        else:
            click.echo("Writing CRL to {}".format(self.crl_file_path))
            with open(self.crl_file_path, "wb") as crl_file:
                crl_file.write(bytes(response.text, "UTF-8"))
