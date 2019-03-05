"""mtls (Mutual TLS) - A cli for creating short-lived client certiicates."""

import os
import platform
import random
import re
import shutil
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
import distro
import gnupg
import json
import requests

__author__ = 'Danny Grove <danny@drgrovell.com>'
VERSION = 'version 0.1'
NAME = 'mtls - Mutual TLS'


class MutualTLS:
    MISSING_CONFIGURATION = """
    Configuration missing for mtls at {}/{}
    """
    MISSING_CONFIGURATION_FOR_SERVER = """
    Configuration missing for {server}:

    Please ensure that you have a configuration for you server similar to:
    [{server}]
    email=foo@example.com
    url=ca.example.com

    For more details see config.ini.example
    """
    CONFIG_FOLDER_PATH = '{}/.config/mtls'.format(os.getenv('HOME'))
    CONFIG_FILE = 'config.ini'
    USER_KEY = '{}.key.gpg'.format(os.getenv('USER'))
    GNUPGHOME = os.getenv('GNUPGHOME', '{}/{}'.format(os.getenv('HOME'),
                                                      '.gnupg'))

    def __init__(self, server):
        self.gpg = gnupg.GPG(gnupghome=self.GNUPGHOME)
        self.gpg.encoding = 'utf-8'
        self.config_file_path = '{config_path}/{config_file}'.format(
            config_path=self.CONFIG_FOLDER_PATH,
            config_file=self.CONFIG_FILE
        )
        self.config = self.get_config()
        self.server = server
        self._make_server_dir_if_missing()
        self.server_in_config()
        self.openssl_format = serialization.PrivateFormat.TraditionalOpenSSL
        self.no_encyption = serialization.NoEncryption()
        self.friendly_name = "{org} - {user}@{hostname}".format(
            org=self.config.get(
                self.server,
                'organization_name'
            ),
            user=str(os.getenv('USER')),
            hostname=str(platform.uname()[1])
        )
        self.pfx_path = '{base_path}/{server}/{server}.pfx'.format(
            base_path=self.CONFIG_FOLDER_PATH,
            server=self.server
        )
        self.cert_file_path = '{base_path}/{server}/{server}.pem'.format(
            base_path=self.CONFIG_FOLDER_PATH,
            server=self.server
        )
        self.ca_cert_file_path = '{base_path}/{server}/{server}_Root_CA.pem'\
            .format(
                base_path=self.CONFIG_FOLDER_PATH,
                server=self.server
            )

    def run(self):
        self._create_db()
        if not self._has_root_cert():
            self._get_and_set_root_cert()
        if sys.platform == 'darwin':
            valid = self.check_valid_cert(name=self.cert_file_path)
        else:
            valid = self.check_valid_cert(name=self.friendly_name)
        if valid is True:
            click.echo("Reusing valid certificate")
            sys.exit(0)
        else:
            self.delete_cert_by_name(self.friendly_name)
        csr = self.get_csr()
        key = self.get_key_or_generate()
        if csr is None:
            csr = self.generate_csr(key)
        else:
            click.echo(click.style(
                'Reusing previously generated CSR for {server}'.format(
                    server=self.server
                ),
                fg='green'
            ))
        cert_str = self.sign_and_send_to_server(csr)
        if cert_str is None:
            click.echo('Could not retrieve certificate from server')
            sys.exit(1)
        cert = self.convert_to_cert(cert_str)
        with open(self.cert_file_path, 'w') as cert_file:
            cert_file.write(
                cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            )
        if cert is None:
            click.echo('Could not convert to certificate')
            sys.exit(1)
        p12 = OpenSSL.crypto.PKCS12()
        pkey = OpenSSL.crypto.PKey.from_cryptography_key(key)
        certificate = OpenSSL.crypto.X509.from_cryptography(cert)
        p12.set_privatekey(pkey)
        p12.set_certificate(certificate)
        p12.set_friendlyname(bytes(self.friendly_name, 'UTF-8'))
        pwd = self._genPW()
        with open(self.pfx_path, 'wb') as f:
            f.write(p12.export(passphrase=bytes(pwd, 'utf-8')))
        self.update_cert_storage(
            self.pfx_path,
            pwd
        )
        self._firefox_notice()

    def _firefox_notice(self):
        click.echo(click.style(
            'Certificates added. If using Firefox you may have to restart ' +
            'before these certificates take effect',
            fg='green'
        ))

    def _has_root_cert(self):
        if sys.platform == 'darwin':
            name = self.ca_cert_file_path
        else:
            name = '{server} Root CA'.format(server=self.server)
        if self.check_valid_cert(
            name,
            usage='CT,T,T',
            is_root=True
        ):
            return True
        return False

    def _get_and_set_root_cert(self):
        # We don't verify this request as we assume that the Root CA Cert is
        # what is backing this server. Since that is the case, SSL validation
        # will fail since the certificate is not in the store.
        r = requests.get(
            '{url}/ca'.format(
                url=self.config.get(self.server, 'url')
            ),
            verify=True
        )
        data = r.json()
        # Update the issuer name directly from the server into your config
        self.config.set(self.server, 'issuer', data['issuer'])
        self.update_config()
        # Write the file to the CA Cert File path so that it's accessible to
        # the user and subsequent calls later.
        with open(self.ca_cert_file_path, 'w') as ca_cert:
            ca_cert.write(data['cert'])
        self.add_root_ca_to_store(self.ca_cert_file_path)

    def add_root_ca_to_store(self, ca_cert_file_path):
        click.echo('Adding root certificate to certificate store...')
        paths = self._get_certdb_paths()
        org = self.config.get(
            self.server,
            'organization_name'
        )
        if sys.platform == 'darwin':
            cmds = []
            add_trust_keychain = [
                'security',
                'add-trusted-cert',
                '-p',
                'ssl',
                ca_cert_file_path
            ]
            import_keychain = [
                'security',
                'import',
                ca_cert_file_path
            ]
            cmds = [
                add_trust_keychain,
                import_keychain
            ]
            for cmd in cmds:
                try:
                    self._run_cmd(cmd, capture_output=True)
                except Exception as e:
                    click.echo("Error")
                    click.echo(e)
            # Override paths for darwin to only handle firefox
            paths = self._firefox_certdb_location()
        if sys.platform == 'linux' or sys.platform == 'linux2' or 'darwin':
            for path in paths:
                cmd = [
                    'certutil',
                    '-A',
                    '-d',
                    path,
                    '-t',
                    'CT,CT,CT',
                    '-i',
                    ca_cert_file_path,
                    '-n',
                    '{org} Root CA'.format(org=org)
                ]
                try:
                    output = self._run_cmd(cmd, capture_output=True)
                except Exception as e:
                    click.echo("Error")
                    click.echo(e)

    def delete_cert_by_name(self, name):
        paths = self._get_certdb_paths()
        click.echo(click.style(
            'Deleting invalid/expired certificates for {}'.format(name),
            fg='red'
        ))
        if sys.platform == 'darwin':
            delete_identity_cmd = [
                'security',
                'delete-identity',
                '-c',
                name
            ]
            output = self._run_cmd(delete_identity_cmd, capture_output=True)
            # Override path to just be firefox on darwin for the next command
            paths = self._firefox_certdb_location()
        if sys.platform in ['linux', 'linux2', 'darwin']:
            for path in paths:
                cmd = [
                    'certutil',
                    '-D',
                    '-d',
                    path,
                    '-n',
                    name
                ]

                try:
                    output = self._run_cmd(cmd, capture_output=True)
                except Exception as e:
                    click.echo("Error")
                    click.echo(e)

    def check_valid_cert(self, name=None, usage='V', is_root=False):
        if name is None:
            click.echo('A valid certificate name is required')
            sys.exit(1)
        paths = self._get_certdb_paths()
        is_valid = True
        if self.config.get(self.server, 'issuer', fallback=None) is None:
            # If the config doesn't have an issuer, we can by default know that
            # a user has not received this information from the server or set
            # it themselves and can assume they don't have a certificate yet
            return False
        if sys.platform == 'darwin':
            # Name is the path to the certificate file, because
            # security does not support verification once a certificate is
            # installed, so we must check that:
            # a) the certificate file exist
            # b) is it actually valid
            # We are only checking Keychain as we cannot verify that Firefox is
            # actually installed and we should not be making that assumption.
            cert_exists = os.path.isfile(self.cert_file_path)
            if not cert_exists:
                return False
            if is_root:
                cmd = [
                    'security',
                    'find-certificate',
                    '-c',
                    self.config.get(self.server, 'issuer')
                ]
                find_cert_output = self._run_cmd(cmd, capture_output=True)
                if "The specified item could not be found" in str(
                    find_cert_output.stderr,
                    'UTF-8'
                ):
                    return False
                cmd = [
                    'security',
                    'verify-cert',
                    '-r',
                    self.ca_cert_file_path
                ]
            else:
                find_cert_output = self._run_cmd([
                    'security',
                    'find-identity',
                    '-p',
                    'ssl-client',
                    '-v',
                ], capture_output=True)
                if self.friendly_name not in str(
                    find_cert_output.stdout,
                    'UTF-8'
                ):
                    return False
                if "The specified item could not be found" in str(
                    find_cert_output.stderr,
                    'UTF-8'
                ):
                    return False
                cmd = [
                    'security',
                    'verify-cert',
                    '-c',
                    name,
                    '-r',
                    self.ca_cert_file_path
                ]

            output = self._run_cmd(cmd, capture_output=True)
            if "CSSMERR_TP_NOT_TRUSTED" in str(output.stdout, 'UTF-8'):
                is_valid = False
            if "CSSMERR_TP_CERT_EXPIRED" in str(output.stderr, 'UTF-8'):
                is_valid = False
        elif sys.platform == 'linux' or sys.platform == 'linux2':
            for path in paths:
                cmd = [
                    'certutil',
                    '-V',
                    '-u',
                    usage,
                    '-d',
                    path,
                    '-n',
                    '{name}'.format(name=name)
                ]
                output = self._run_cmd(cmd, capture_output=True)
                if "certificate is invalid" in str(output.stdout, 'UTF-8'):
                    self.delete_cert_by_name(self.friendly_name)
                    is_valid = False
                if "could not find certificate" in str(output.stderr, 'UTF-8'):
                    is_valid = False
                    return is_valid
                if "validation failed" in str(output.stderr, 'UTF-8'):
                    is_valid = False
                    return is_valid

        return is_valid

    def get_csr(self):
        csr_path = '{}/{}.csr.asc'.format(self.CONFIG_FOLDER_PATH, self.server)
        if not os.path.isfile(csr_path):
            return None
        click.echo('Decrypting CSR...')
        csr_str = str(self.gpg.decrypt_file(open(csr_path, 'rb')))
        return x509.load_pem_x509_csr(bytes(csr_str, 'utf-8'),
                                      default_backend())

    def _genPW(self):
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        chars += '1234567890'
        chars += '!@#$%^&*()-_+=|?><,.'
        pw = ""
        for c in range(50):
            pw += random.choice(chars)
        if len(pw) < 50:
            click.echo(
                click.style(
                    'Failed to generate appropriate password.',
                    fg='red',
                    bold=True
                )
            )
            sys.exit(1)
        if re.search('[0-9]+', pw) is None:
            pw = self._genPW()
        return pw

    def convert_to_cert(self, cert):
        try:
            cert = bytes(str(cert), 'utf-8')
            cert = x509.load_pem_x509_certificate(
                cert,
                backend=default_backend()
            )
            return cert
        except Exception as e:
            click.echo(
                click.style(
                    'Failure to load PEM x509 Certificate: {}'.format(e),
                    fg='red'
                )
            )

    def _run_cmd(self, args, capture_output=False):
        return subprocess.run(args, capture_output=capture_output)

    def update_cert_storage(self, cert_file_path, cert_pw):
        if sys.platform == 'linux' or sys.platform == 'linux2':
            paths = self._get_certdb_paths()
            for path in paths:
                try:
                    self._run_cmd([
                        'pk12util',
                        '-i',
                        cert_file_path,
                        '-d',
                        path,
                        '-W',
                        cert_pw,
                        '-n',
                        self.config.get(self.server, 'hostname')
                    ], capture_output=True)
                except Exception as e:
                    cse = 'Could not add certificate to certificate store'
                    click.echo(click.style(cse, fg='red'))
                    click.echo(e)
        elif sys.platform == 'darwin':
            try:
                # Add to keychain
                self._run_cmd([
                    'security',
                    'import',
                    cert_file_path,
                    '-f',
                    'pkcs12',
                    '-P',
                    cert_pw
                ], capture_output=True)
            except Exception as e:
                click.echo(
                    'Could not add certificate to certificate store'
                )
            try:
                # Add to FireFox Store
                paths = self._firefox_certdb_location()
                for path in paths:
                    cmd = [
                        'pk12util',
                        '-i',
                        cert_file_path,
                        '-d',
                        path,
                        '-W',
                        cert_pw,
                        '-n',
                        self.config.get(self.server, 'hostname')
                    ]
                    self._run_cmd(cmd, capture_output=True)
            except Exception as e:
                click.echo(
                    click.style(
                        'Could not add certificate to certificate store',
                        fg='red'
                    )
                )
                click.echo(e)
        else:
            try:
                self._run_cmd([
                    'certutil.exe',
                    '-viewstore',
                    '-user',
                    'root'
                ], capture_output=True)
            except Exception as e:
                click.echo('Could not add certificate to certificate store')
                click.echo(e)

    def _make_server_dir_if_missing(self):
        path = '{config}/{server}'.format(
            config=self.CONFIG_FOLDER_PATH,
            server=self.server
        )
        if not os.path.isdir(path):
            os.makedirs(path)

    def _create_db(self):
        path = self._primary_certdb_location()
        if sys.platform == 'linux' or sys.platform == 'linux2':
            if not os.path.isdir(path):
                os.makedirs(path)
                # This assumes that you're using an encrypted hard drive
                # Othewise we need to look into a way to allow user input
                # Probably swapping subprocess.call with subprocess.popen so
                # that users can manually enter passwords
                click.echo(
                    click.style(
                        "Making nssdb at {}".format(path),
                        fg='green'
                    )
                )
                subprocess.call([
                    "certutil",
                    "-d",
                    path,
                    "-N",
                    "--empty-password"
                ])

    def _get_certdb_paths(self):
        paths = [
            self._primary_certdb_location(),
        ] + self._firefox_certdb_location()
        return paths

    def _primary_certdb_location(self):
        return os.path.join(os.getenv('HOME'), '.pki/nssdb')

    def _firefox_certdb_location(self):
        base_path = None
        paths = []
        if sys.platform == 'linux' or sys.platform == 'linux2':
            base_path = os.path.join(
                os.getenv('HOME'),
                '.mozilla/firefox'
            )
        elif sys.platform == 'darwin':
            # Make directory if it doesn't exist
            base_path = os.path.join(
                os.getenv('HOME'),
                'Library/Application Support/Firefox/Profiles/'
            )
        elif sys.platform == 'win32':
            base_path = os.path.join(
                os.getenv('USERPROFILE'),
                '\\AppData\\Local\\Firefox'
            )
        if base_path is not None:
            posix_paths = list(Path(base_path).rglob('cert*.db'))
            for pp in posix_paths:
                paths.append('/'.join(str(pp).split('/')[:-1]))
        return paths

    @staticmethod
    def print_version(ctx, param, value):
        """Prints the version of the application."""
        if not value or ctx.resilient_parsing:
            return
        click.echo(NAME + ' ' + VERSION)
        ctx.exit()

    def check_for_config(self):
        """Check if the config exists, otherwise exit."""
        config_dir_exists = os.path.isdir(self.CONFIG_FOLDER_PATH)
        config_exists = os.path.isfile(self.config_file_path)

        if not config_dir_exists or not config_exists:
            msg = self.MISSING_CONFIGURATION.format(
                self.CONFIG_FOLDER_PATH,
                self.CONFIG_FILE
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

    def update_config(self):
        click.echo(
            click.style(
                'Updating config file settings for {server}'.format(
                    server=self.server
                ),
                fg='green'
            )
        )
        with open(self.config_file_path, 'w') as config_file:
            self.config.write(config_file)

    def server_in_config(self):
        """Determines if the set server is in the config, otherwise exit."""
        if self.server is None and len(self.config.sections()) > 1:
            click.echo('You have multiple servers configured, please ' +
                       'selection one with the --server (-s) option')
        if self.server not in self.config:
            click.echo(self.MISSING_CONFIGURATION_FOR_SERVER)
            sys.exit(1)

    def encrypt(self, data, recipient, sign=False):
        """Encrypt data using PGP to recipient."""
        if sign is True:
            click.echo('Encrypting and Signing data...')
        return self.gpg.encrypt(data, recipient, sign=sign)

    def get_key_or_generate(self):
        """Get users key from file or generate a new RSA Key.

        Returns:
            key - RSA Key
        """
        key = None
        config_folder = self.CONFIG_FOLDER_PATH
        user_key = self.USER_KEY
        key_path = f'{config_folder}/{user_key}'
        if os.path.isfile(key_path):
            click.echo('Decrypting User Key...')
            encrypted_key_file = open(key_path, 'rb')
            key_data = self.gpg.decrypt_file(encrypted_key_file)
            byte_key_data = bytes(str(key_data), 'utf-8')
            key = serialization.load_pem_private_key(byte_key_data,
                                                     password=None,
                                                     backend=default_backend())
        else:
            click.echo('Generating User Key')
            key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=4096,
                    backend=default_backend())
            key_data = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=self.openssl_format,
                encryption_algorithm=self.no_encyption
            )
            user_fingerprint = self.config.get(self.server, 'fingerprint')
            encrypted_key = self.encrypt(key_data, user_fingerprint)
            user_email = self.config.get(self.server, 'email')
            click.echo('Encrypting file to {}'.format(user_email))
            with open(key_path, 'w') as f:
                f.write(str(encrypted_key))
        return key

    def generate_csr(self, key):
        """Generates a CSR.

        Args:
            key - The users key

        Returns:
            csr - The CSR
        """
        click.echo(
            click.style(
                'Generating CSR for {server}'.format(server=self.server),
                fg='yellow'
            )
        )
        country = self.config.get(self.server, 'country')
        state = self.config.get(self.server, 'state')
        locality = self.config.get(self.server, 'locality')
        organization_name = self.config.get(self.server, 'organization_name')
        email = self.config.get(self.server, 'email')
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, self.friendly_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
        ])).sign(key, hashes.SHA256(), default_backend())
        csr_fname = '{}.csr.asc'.format(self.server)
        with open(
            '{config}/{server}/{csr}'.format(
                config=self.CONFIG_FOLDER_PATH,
                server=self.server,
                csr=csr_fname
            ),
            'wb'
        ) as f:
            enc_csr = self.encrypt(
                csr.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                self.config.get(self.server, 'fingerprint')
            )
            f.write(bytes(str(enc_csr), 'utf-8'))
        return csr

    def _get_path(self, path):
        """Gets the absolute path given a path."""
        if not os.path.isabs(path):
            return os.path.abspath(
                os.path.join(
                    self.CONFIG_FOLDER_PATH,
                    path
                )
            )

    def send_request(self, url, payload):
        return requests.post(
            url,
            json=payload,
            verify=True
        )

    def sign_and_send_to_server(self, csr):
        """Sign and send to server.

        Args:
            csr - The CSR

        Returns:
            cert - the certificate
        """
        csr_public_bytes = csr.public_bytes(serialization.Encoding.PEM)
        click.echo('Signing CSR for verification on server...')
        signature = self.gpg.sign(
            csr_public_bytes,
            keyid=self.config.get(self.server, 'fingerprint'),
            detach=True,
            clearsign=True
        )
        payload = {
            'csr': csr_public_bytes.decode('utf-8'),
            'signature': str(signature),
            'lifetime': self.config.get(
                self.server,
                'lifetime',
                fallback=64800
            ),
            'host': self.config.get(self.server, 'hostname'),
            'type': 'CREATE_CERTIFICATE'
        }
        server_url = self.config.get(self.server, 'url')
        response = self.send_request(server_url, payload)
        response = response.json()
        if response.get('error', False):
            click.echo(response.get('msg'))
            sys.exit(1)
        return str(response['cert'])


@click.command()
@click.option('--server', '-s')
@click.option('--version', '-v',
              is_flag=True, callback=MutualTLS.print_version,
              expose_value=False, is_eager=True)
def main(server=None):
    if server is None:
        click.echo('A server must be specified.')
        sys.exit(1)
    if sys.platform == 'win32' or sys.platform == 'cygwin':
        click.echo(click.style(
            'Your platform is not currently supported',
            fg='red'
        ))
    mtls = MutualTLS(server)
    mtls.run()


if __name__ == '__main__':
    main()
