import logging
import platform
import os
import random
import re
import subprocess
import time
import unittest

from click.testing import CliRunner
from configparser import ConfigParser
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import click
import docker
import gnupg
import tempfile

from cli import cli

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


#logging.disable(logging.CRITICAL)
MTLS_SERVER_VERSION = os.environ.get('MTLS_SERVER_VERSION') or 'v0.10.0'


def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )


def gen_passwd():
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    pw = ""
    for c in range(50):
        pw += random.choice(chars)
    return pw


def generate_csr(key, common_name, email):
    country = 'US'
    state = 'CA'
    locality = 'San Francisco'
    organization_name = 'My Org'
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email)
    ])).sign(key, hashes.SHA256(), default_backend())


def gen_pgp_key(email, password, gpg):
    input_data = gpg.gen_key_input(
        name_email=email,
        passphrase=password
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
        csr = generate_csr(self.key, common_name)
        self.__csrs.append(csr)
        return csr


class TestCli(unittest.TestCase):
    def setUp(self):
        TMPDIR_PREFIX = os.environ.get('TMPDIR') or '/tmp/'
        self.USER_GNUPGHOME = tempfile.TemporaryDirectory(prefix=TMPDIR_PREFIX)
        self.HOME = tempfile.TemporaryDirectory(prefix=TMPDIR_PREFIX)
        self.ADMIN_GNUPGHOME = tempfile.TemporaryDirectory(
            prefix=TMPDIR_PREFIX
        )
        self.server_config_dir = tempfile.TemporaryDirectory(
            prefix=TMPDIR_PREFIX
        )
        self.seed_dir = tempfile.TemporaryDirectory(prefix=TMPDIR_PREFIX)
        self.user_gpg = gnupg.GPG(gnupghome=self.USER_GNUPGHOME.name)
        self.admin_gpg = gnupg.GPG(gnupghome=self.ADMIN_GNUPGHOME.name)
        self.user = User(
            'test@example.com',
            gen_passwd(),
            generate_key(),
            self.user_gpg
        )
        self.admin =User(
            'test@example.com',
            gen_passwd(),
            generate_key(),
            self.admin_gpg
        )
        self.docker = docker.from_env()
        file_path = os.path.join(
            self.seed_dir.name,
            '{}.asc'.format(self.admin.pgp_key.fingerprint),
        )
        with open(file_path, 'w') as f:
            f.write(self.admin_gpg.export_keys(self.admin.pgp_key.fingerprint))
        self.server_config = ConfigParser()
        self.server_config_path = os.path.join(
            self.server_config_dir.name,
            'config.ini'
        )
        self.server_config['mtls'] = {
            'min_lifetime': '10',
            'max_lifetime': '0'
        }
        self.server_config['ca'] = {
            'key': 'secrets/certs/authority/RootCA.key',
            'cert': 'secrets/certs/authority/RootCA.pem',
            'issuer': 'My Company Name',
            'alternate_name': '*.myname.com'
        }
        self.server_config['gnupg'] = {
            'user': 'secrets/gnupg',
            'admin': 'secrets/gnupg_admin'
        }
        self.server_config['storage'] ={
            'engine': 'sqlite3'
        }
        self.server_config['storage.sqlite3'] = {
            'db_path': 'mtls-server.db'
        }
        with open(self.server_config_path, 'w') as configfile:
            self.server_config.write(configfile)
        volumes = {}
        volumes[self.seed_dir.name] = {
            'bind': '/tmp/seeds',
            'mode': 'ro'
        }
        volumes[self.server_config_path] = {
            'bind': '/home/mtls/config.ini',
            'mode': 'rw'
        }
        self.server = self.docker.containers.run(
            'drgrove/mtls-server:{version}'.format(
                version=MTLS_SERVER_VERSION
            ),
            detach=True,
            volumes=volumes,
            remove=True,
            ports={'4000/tcp': 4000}
        )
        self.env = {
            'GNUPGHOME': self.ADMIN_GNUPGHOME.name,
            'HOME': self.HOME.name,
            'USER': 'test',
            'HOST': str(platform.uname()[1])
        }
        self.runner = CliRunner(env=self.env)
        self.config = ConfigParser()
        self.config['DEFAULT'] = {
            'name': 'John Doe',
            'email': 'johndoe@example.com',
            'fingerprint': self.admin.pgp_key.fingerprint,
            'country': 'US',
            'state': 'CA',
            'locality': 'Mountain View',
            'organization_name': 'My Org'
        }
        self.config['test'] = {
            'lifetime': 60,
            'url': 'http://localhost:4000',
        }
        self.config_path = os.path.join(
            self.HOME.name,
            'config.ini'
        )
        with open(self.config_path, 'w') as configfile:
            self.config.write(configfile)

    def tearDown(self):
        self.USER_GNUPGHOME.cleanup()
        self.ADMIN_GNUPGHOME.cleanup()
        self.HOME.cleanup()
        self.server.stop()
        time.sleep(10)
        self.seed_dir.cleanup()
        self.server_config_dir.cleanup()

    def test_show_help(self):
        result = self.runner.invoke(cli, ['--help'])
        self.assertEqual(result.exit_code, 0)

    def test_create_certificate(self):
        result = self.runner.invoke(
            cli,
            [
                '-c',
                self.config_path,
                '-s',
                'test',
                '--gpg-password',
                self.admin.password,
                'create-certificate'
            ]
        )
        self.assertEqual(result.exit_code, 0)
        # TODO(drGrove): Add ssl test to hit /test endpoint

    def test_revoke_certificate(self):
        create_result = self.runner.invoke(
            cli,
            [
                '-c',
                self.config_path,
                '-s',
                'test',
                '--gpg-password',
                self.admin.password,
                'create-certificate'
            ]
        )
        cert_file_path = os.path.join(self.HOME.name, 'test/test.pem')
        with open(cert_file_path, 'rb') as cert_file:
            cert = x509.load_pem_x509_certificate(
                cert_file.read(),
                default_backend()
            )
        result = self.runner.invoke(
            cli,
            [
                '-c',
                self.config_path,
                '-s',
                'test',
                '--gpg-password',
                self.admin.password,
                'revoke-certificate',
                '--serial-number',
                str(cert.serial_number)
            ]
        )
        self.assertEqual(result.exit_code, 0)
        # TODO(drGrove): Add ssl test to hit /test endpoint
