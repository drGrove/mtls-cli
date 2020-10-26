import logging
import platform
import os
import random
import re
import subprocess
import time
import traceback
import unittest

from click.testing import CliRunner
from configparser import ConfigParser
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import click
import docker
import gnupg
import tempfile
import requests

from mtls.cli import cli


def getListOfFiles(dirName):
    listOfFile = os.listdir(dirName)
    allFiles = list()
    for entry in listOfFile:
        fullPath = os.path.join(dirName, entry)
        if os.path.isdir(fullPath):
            allFiles = allFiles + getListOfFiles(fullPath)
        else:
            allFiles.append(fullPath)
    return allFiles


logging.disable(logging.CRITICAL)
MTLS_SERVER_VERSION = os.environ.get("MTLS_SERVER_VERSION") or "v0.17.0"
MTLS_IMAGE = os.environ.get("MTLS_IMAGE") or "drgrove/mtls-server"


def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=1024, backend=default_backend()
    )


def gen_passwd():
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    pw = ""
    for c in range(50):
        pw += random.choice(chars)
    return pw


def generate_csr(key, common_name, email):
    country = "US"
    state = "CA"
    locality = "San Francisco"
    organization_name = "My Org"
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, organization_name
                    ),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
                ]
            )
        )
        .sign(key, hashes.SHA256(), default_backend())
    )


def gen_pgp_key(email, password, gpg):
    input_data = gpg.gen_key_input(
        name_email=email, passphrase=password, key_type="RSA", key_length=1024
    )
    return gpg.gen_key(input_data)


class User:
    def __init__(self, email, password, key, gpg=None):
        self.gpg = gpg
        self.email = email
        self.password = password
        self.key = key
        self.pgp_key = gen_pgp_key(email, password, gpg)
        self.fingerprint = self.pgp_key.fingerprint
        self.__csrs = []

    @property
    def email(self):
        return self.__email

    @email.setter
    def email(self, email):
        self.__email = email

    @property
    def password(self):
        return self.__password

    @password.setter
    def password(self, password):
        self.__password = password

    @property
    def pgp_key(self):
        return self.__pgp_key

    @pgp_key.setter
    def pgp_key(self, pgp_key):
        self.__pgp_key = pgp_key

    @property
    def csrs(self):
        return self.__csrs

    def gen_csr(self, common_name=None):
        if common_name is None:
            common_name = self.email
        csr = generate_csr(self.key, common_name, self.email)
        self.__csrs.append(csr)
        return csr


class TestCliBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TMPDIR_PREFIX = os.environ.get("TMP_DIR") or "/tmp/"
        TMPDIR_PREFIX = os.path.expanduser(TMPDIR_PREFIX)
        VERBOSE_GPG = os.environ.get("DEBUG_GNUPG") or False
        cls.seed_dir = tempfile.TemporaryDirectory(dir=TMPDIR_PREFIX)
        for subpath in ["user", "admin"]:
            os.makedirs(
                "{base}/{subpath}".format(
                    base=cls.seed_dir.name, subpath=subpath
                )
            )
        cls.server_config_dir = tempfile.TemporaryDirectory(dir=TMPDIR_PREFIX)
        cls.docker = docker.from_env()
        cls.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory(dir=TMPDIR_PREFIX)
        cls.admin_gpg = gnupg.GPG(
            gnupghome=cls.ADMIN_GNUPGHOME.name, verbose=VERBOSE_GPG
        )
        cls.admin = User(
            "johndoe@example.com", gen_passwd(), generate_key(), cls.admin_gpg
        )
        file_path = os.path.join(
            cls.seed_dir.name,
            "admin/{}.asc".format(cls.admin.pgp_key.fingerprint),
        )
        with open(file_path, "w") as f:
            f.write(cls.admin_gpg.export_keys(cls.admin.pgp_key.fingerprint))
        cls.USER_GNUPGHOME = tempfile.TemporaryDirectory(dir=TMPDIR_PREFIX)
        cls.user_gpg = gnupg.GPG(
            gnupghome=cls.USER_GNUPGHOME.name, verbose=VERBOSE_GPG
        )
        cls.user = User(
            "johndoe@example.com", gen_passwd(), generate_key(), cls.user_gpg
        )
        file_path = os.path.join(
            cls.seed_dir.name,
            "user/{}.asc".format(cls.user.pgp_key.fingerprint),
        )
        with open(file_path, "w") as f:
            f.write(cls.user_gpg.export_keys(cls.user.pgp_key.fingerprint))
        cls.server_config = ConfigParser()
        cls.server_config_path = os.path.join(
            cls.server_config_dir.name, "config.ini"
        )
        cls.server_config["mtls"] = {
            "min_lifetime": "10",
            "max_lifetime": "1000",
        }
        cls.server_config["ca"] = {
            "key": "secrets/certs/authority/RootCA.key",
            "cert": "secrets/certs/authority/RootCA.pem",
            "issuer": "My Company Name",
            "alternate_name": "*.myname.com",
        }
        cls.server_config["gnupg"] = {
            "user": "secrets/gnupg",
            "admin": "secrets/gnupg_admin",
        }
        cls.server_config["storage"] = {"engine": "sqlite3"}
        cls.server_config["storage.sqlite3"] = {"db_path": "mtls-server.db"}
        with open(cls.server_config_path, "w") as configfile:
            cls.server_config.write(configfile)
        volumes = {}
        volumes[cls.seed_dir.name] = {"bind": "/tmp/seeds", "mode": "ro"}
        volumes[cls.server_config_path] = {
            "bind": "/home/mtls/config.ini",
            "mode": "rw",
        }
        cls.server = cls.docker.containers.run(
            "{image}:{version}".format(
                version=MTLS_SERVER_VERSION, image=MTLS_IMAGE
            ),
            detach=True,
            volumes=volumes,
            remove=True,
            ports={"4000/tcp": 4000},
        )
        while True:
            try:
                resp = requests.get("http://localhost:4000/version")
                if resp.status_code == 200:
                    break
            except Exception:
                # requests throws an error now if the connection is reset
                # we don't care about it, we're just waiting for the server
                # to come up
                pass
        cls.HOME = tempfile.TemporaryDirectory(dir=TMPDIR_PREFIX)
        cls.env = {
            "GNUPGHOME": cls.ADMIN_GNUPGHOME.name,
            "HOME": cls.HOME.name,
            "USER": "test",
            "HOST": str(platform.uname()[1]),
        }
        cls.runner = CliRunner(env=cls.env)
        cls.config = ConfigParser()
        cls.config["DEFAULT"] = {
            "name": "John Doe",
            "email": "johndoe@example.com",
            "fingerprint": cls.admin.pgp_key.fingerprint,
            "country": "US",
            "state": "CA",
            "locality": "Mountain View",
            "organization_name": "My Org",
        }
        cls.config["test"] = {"lifetime": 60, "url": "http://localhost:4000"}
        cls.config_path = os.path.join(cls.HOME.name, "config.ini")
        with open(cls.config_path, "w") as configfile:
            cls.config.write(configfile)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.docker.close()
        cls.USER_GNUPGHOME.cleanup()
        cls.ADMIN_GNUPGHOME.cleanup()
        cls.seed_dir.cleanup()
        cls.server_config_dir.cleanup()
        cls.HOME.cleanup()


class TestCliAsAdmin(TestCliBase):
    def test_show_help(self):
        result = self.runner.invoke(cli, ["--help"])
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_create_certificate(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "certificate",
                "create",
            ],
        )
        self.assertEqual(result.exit_code, 0)

    def test_create_certificate_with_cli_friendly_name_option(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "certificate",
                "create",
                "--friendly-name",
                "Foo Bar",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        cert_file_path = os.path.join(self.HOME.name, "test/test.pem")
        with open(cert_file_path, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(
                cert_file.read(), default_backend()
            )
        self.assertEqual(
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "My Org - Foo Bar",
        )

    def test_create_certificate_with_cli_email_option_no_common_name(self):
        input_email = "test1245566@example.com"
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "certificate",
                "create",
                "--user-email",
                input_email,
            ],
        )
        self.assertEqual(result.exit_code, 1, msg=result.exc_info)

    def test_create_certificate_with_cli_email_option(self):
        input_email = "test1245566@example.com"
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "certificate",
                "create",
                "--common-name",
                input_email,
                "--user-email",
                input_email,
            ],
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)
        cert_file_path = os.path.join(self.HOME.name, "test/test.pem")
        with open(cert_file_path, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(
                cert_file.read(), default_backend()
            )
        email = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[
            0
        ].value
        self.assertEqual(email, input_email)

    def test_create_certificate_with_cli_output_option(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "certificate",
                "create",
                "-o",
                self.HOME.name + "/me.pfx",
            ],
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)
        self.assertTrue(
            os.path.isfile("{}/{}".format(self.HOME.name, "me.pfx"))
        )
        self.assertTrue(
            os.path.isfile("{}/{}".format(self.HOME.name, "me.password.asc"))
        )

    def test_revoke_certificate(self):
        cert_file_path = os.path.join(self.HOME.name, "test/test.pem")
        with open(cert_file_path, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(
                cert_file.read(), default_backend()
            )
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "certificate",
                "revoke",
                "--serial-number",
                str(cert.serial_number),
            ],
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_add_user_by_fingerprint(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "add",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_add_user_by_email(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "add",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_remove_user_by_fingerprint(self):
        add_user_result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "add",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
            input="0",
        )
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "remove",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_remove_user_by_email(self):
        add_user_result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "add",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "add",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_add_admin_by_fingerprint(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "add",
                "--admin",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_add_admin_by_email(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "add",
                "--admin",
                "--keyserver",
                "keys.openpgp.org",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_remove_admin_by_fingerprint(self):
        add_user_result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "add",
                "--admin",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
            input="0",
        )
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "remove",
                "--admin",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_remove_admin_by_email(self):
        add_user_result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "add",
                "--admin",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "user",
                "add",
                "--admin",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def get_crl_to_output(self):
        result = self.runner.invoke(
            cli, ["-s", "test", "certificate", "crl", "-o"]
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)
        crl = x509.load_pem_x509_crl(
            data=bytes(result.output, "UTF-8"), backend=default_backend()
        )
        self.assertIsInstance(crl, openssl.x509._CertificateRevocationList)
        self.assertIsInstance(
            crl.get_revoked_certificate_by_serial_number(rev_serial_num),
            openssl.x509._RevokedCertificate,
        )
        self.assertIn(
            "-----BEGIN X509 CRL-----",
            crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8"),
        )
        self.assertIn(
            "-----END X509 CRL-----",
            crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8"),
        )

    def get_crl_to_file(self):
        result = self.runner.invoke(
            cli, ["-s", "test", "certificate", "crl", "-no"]
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)
        with open("{base}/test/test.crl".format(self.HOME.name), "rb") as crl:
            crl = x509.load_pem_x509_crl(
                data=f.read(), backend=default_backend()
            )
            self.assertIsInstance(crl, openssl.x509._CertificateRevocationList)
            self.assertIsInstance(
                crl.get_revoked_certificate_by_serial_number(rev_serial_num),
                openssl.x509._RevokedCertificate,
            )
            self.assertIn(
                "-----BEGIN X509 CRL-----",
                crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8"),
            )
            self.assertIn(
                "-----END X509 CRL-----",
                crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8"),
            )


class TestCliAsUser(TestCliBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env = {
            "GNUPGHOME": cls.USER_GNUPGHOME.name,
            "HOME": cls.HOME.name,
            "USER": "test",
            "HOST": str(platform.uname()[1]),
        }
        cls.runner = CliRunner(env=cls.env)
        cls.config = ConfigParser()
        cls.config["DEFAULT"] = {
            "name": "John Doe",
            "email": "johndoe@example.com",
            "fingerprint": cls.user.pgp_key.fingerprint,
            "country": "US",
            "state": "CA",
            "locality": "Mountain View",
            "organization_name": "My Org",
        }
        cls.config["test"] = {"lifetime": 60, "url": "http://localhost:4000"}
        cls.config_path = os.path.join(cls.HOME.name, "config.ini")
        with open(cls.config_path, "w") as configfile:
            cls.config.write(configfile)

    def test_show_help(self):
        result = self.runner.invoke(cli, ["--help"])
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_init(self):
        result = self.runner.invoke(
            cli,
            ["-c", f"{self.HOME.name}/config2.ini", "init"],
            input="Test User\njohndoe@example.com\n1\nn",
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_create_certificate(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "certificate",
                "create",
            ],
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_create_certificate_with_cli_email_option(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.admin.password,
                "certificate",
                "create",
                "--user-email",
                "test1245566@example.com",
            ],
        )
        self.assertEqual(result.exit_code, 1, msg=result.exc_info)

    def test_revoke_certificate(self):
        cert_file_path = os.path.join(self.HOME.name, "test/test.pem")
        with open(cert_file_path, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(
                cert_file.read(), default_backend()
            )
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "certificate",
                "revoke",
                "--serial-number",
                str(cert.serial_number),
            ],
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

    def test_add_user_by_fingerprint(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "add",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
        )
        self.assertEqual(result.exit_code, 1, msg=result.exc_info)

    def test_add_user_by_email(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "add",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 1, msg=result.exc_info)

    def test_remove_user_by_fingerprint(self):
        add_user_result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "add",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
            input="0",
        )
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "remove",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 1, msg=result.exc_info)

    def test_remove_user_by_email(self):
        add_user_result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "add",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "add",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 1, msg=result.exc_info)

    def test_add_admin_by_fingerprint(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "add",
                "--admin",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
        )
        self.assertEqual(result.exit_code, 1, msg=result.exc_info)

    def test_add_admin_by_email(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "add",
                "--admin",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 1, msg=result.exc_info)

    def test_remove_admin_by_fingerprint(self):
        add_user_result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "add",
                "--admin",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
            input="0",
        )
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "remove",
                "--admin",
                "--fingerprint",
                "C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 1, msg=result.exc_info)

    def test_remove_admin_by_email(self):
        add_user_result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "add",
                "--admin",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "user",
                "add",
                "--admin",
                "--keyserver",
                "keyserver.ubuntu.com",
                "--email",
                "danny@drgrovellc.com",
            ],
            input="0",
        )
        self.assertEqual(result.exit_code, 1, msg=result.exc_info)

    def get_crl_to_output(self):
        result = self.runner.invoke(
            cli, ["-s", "test", "certificate", "crl", "-o"]
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)
        crl = x509.load_pem_x509_crl(
            data=bytes(result.output, "UTF-8"), backend=default_backend()
        )
        self.assertIsInstance(crl, openssl.x509._CertificateRevocationList)
        self.assertIsInstance(
            crl.get_revoked_certificate_by_serial_number(rev_serial_num),
            openssl.x509._RevokedCertificate,
        )
        self.assertIn(
            "-----BEGIN X509 CRL-----",
            crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8"),
        )
        self.assertIn(
            "-----END X509 CRL-----",
            crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8"),
        )

    def get_crl_to_file(self):
        result = self.runner.invoke(
            cli, ["-s", "test", "certificate", "crl", "-no"]
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)
        with open("{base}/test/test.crl".format(self.HOME.name), "rb") as crl:
            crl = x509.load_pem_x509_crl(
                data=f.read(), backend=default_backend()
            )
            self.assertIsInstance(crl, openssl.x509._CertificateRevocationList)
            self.assertIsInstance(
                crl.get_revoked_certificate_by_serial_number(rev_serial_num),
                openssl.x509._RevokedCertificate,
            )
            self.assertIn(
                "-----BEGIN X509 CRL-----",
                crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8"),
            )
            self.assertIn(
                "-----END X509 CRL-----",
                crl.public_bytes(serialization.Encoding.PEM).decode("UTF-8"),
            )


class TestCliOptions(TestCliBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env = {
            "GNUPGHOME": cls.USER_GNUPGHOME.name,
            "HOME": cls.HOME.name,
            "USER": "test",
            "HOST": str(platform.uname()[1]),
        }
        cls.runner = CliRunner(env=cls.env)
        cls.config = ConfigParser()
        cls.config["DEFAULT"] = {
            "name": "John Doe",
            "email": "johndoe@example.com",
            "fingerprint": cls.user.pgp_key.fingerprint,
            "country": "US",
            "state": "CA",
            "locality": "Mountain View",
            "organization_name": "My Org",
        }
        cls.config["test"] = {"lifetime": 60, "url": "http://localhost:4000"}
        cls.config_path = os.path.join(cls.HOME.name, "config.ini")
        with open(cls.config_path, "w") as configfile:
            cls.config.write(configfile)

    def test_add_server(self):
        server_url = "https://certauth.foo.bar"
        result = self.runner.invoke(
            cli,
            ["-c", self.config_path, "server", "add", "foo"],
            input=server_url + "\n",
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)
        config = ConfigParser()
        config.read(self.config_path)
        self.assertEqual(config.get("foo", "url"), server_url)

    def test_remove_server(self):
        result = self.runner.invoke(
            cli, ["-c", self.config_path, "server", "remove", "foo"]
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)
        config = ConfigParser()
        config.read(self.config_path)
        self.assertFalse(config.has_section("foo"))

    def test_set_user_config(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "config",
                "organization_name",
                "My New Org",
            ],
        )
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)
        config = ConfigParser()
        config.read(self.config_path)
        self.assertEqual(
            config.get("DEFAULT", "organization_name"), "My New Org"
        )


class TestCliOptionalConfigItems(TestCliBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env = {
            "GNUPGHOME": cls.USER_GNUPGHOME.name,
            "HOME": cls.HOME.name,
            "USER": "test",
            "HOST": str(platform.uname()[1]),
        }
        cls.runner = CliRunner(env=cls.env)
        cls.config = ConfigParser()
        cls.config["DEFAULT"] = {
            "name": "John Doe",
            "email": "johndoe@example.com",
            "fingerprint": cls.user.pgp_key.fingerprint,
            "organization_name": "My Org",
        }
        cls.config["test"] = {"lifetime": 60, "url": "http://localhost:4000"}
        cls.config_path = os.path.join(cls.HOME.name, "config.ini")
        with open(cls.config_path, "w") as configfile:
            cls.config.write(configfile)

    def test_create_certificate(self):
        result = self.runner.invoke(
            cli,
            [
                "-c",
                self.config_path,
                "-s",
                "test",
                "--gpg-password",
                self.user.password,
                "certificate",
                "create",
            ],
        )
        if result.exception:
            traceback.print_exception(*result.exc_info)
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)

class TestCliNoConfig(TestCliBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env = {
            "GNUPGHOME": cls.USER_GNUPGHOME.name,
            "HOME": cls.HOME.name,
            "XDG_CONFIG_HOME": f"{cls.HOME.name}/.config",
            "USER": "test",
            "HOST": str(platform.uname()[1]),
        }
        cls.runner = CliRunner(env=cls.env)
        cls.config["DEFAULT"] = {
            "name": "John Doe",
            "email": "johndoe@example.com",
            "fingerprint": cls.user.pgp_key.fingerprint,
            "organization_name": "My Org",
        }

    def test_add_config_missing_file(self):
        config_path = f"{self.env['XDG_CONFIG_HOME']}/mtls/config.ini"
        result = self.runner.invoke(
            cli,
            [
                "-c",
                config_path,
                "config",
                "name",
                "\"Test User\""
            ]
        )
        if result.exception:
            traceback.print_exception(*result.exc_info)
        self.assertEqual(result.exit_code, 0, msg=result.exc_info)
