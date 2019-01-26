"""mtls (Mutual TLS) - A cli for creating short-lived client certiicates."""

import os
import shutil
import subprocess
import sys
from configparser import ConfigParser

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import click
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
        self.config = self.get_config()
        self.server = server
        self.server_in_config()

    def run(self):
        key = self.get_key_or_generate()
        csr = self.generate_csr(key)
        cert_str = self.sign_and_send_to_server(csr)
        if cert_str is None:
            click.echo('Could not retrieve certificate from server')
            sys.exit(1)
        click.echo('Decrypting Cert from server...')
        cert = self.convert_to_cert(cert_str)
        if cert is None:
            click.echo('Could not convert to certificate')
            sys.exit(1)
        cert_file = '{}.crt'.format(self.server)
        cert_file_path = '{}/{}'.format(self.CONFIG_FOLDER_PATH, cert_file)
        with open(cert_file_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))

        paths = []
        paths.append(self._firefox_cert_location())
        self.place_certificates(cert_file_path, cert_file, paths)
        self.update_cert_storage(cert_file_path)

    def convert_to_cert(self, cert):
        try:
            cert = bytes(str(cert), 'utf-8')
            cert = x509.load_pem_x509_certificate(
                cert,
                backend=default_backend()
            )
            return cert
        except Exception as e:
            print('Failure to load PEM x509 Certificate: {}'.format(e))

    def update_cert_storage(self, cert_file_path):
        command = None
        if sys.platform == 'linux' or sys.platform == 'linux2':
            nssdb_path = os.path.join(os.getenv('HOME'), '.pki/nssdb')
            if not os.path.isdir(nssdb_path):
                os.makedirs(nssdb_path)
                subprocess.call([
                    "certutil",
                    "-d",
                    nssdb_path,
                    "-N",
                    "--empty-password"
                ])
            command = [
                'certutil',
                '-A',
                '-d',
                nssdb_path,
                '-t',
                '"C,,"',
                '-n',
                self.server,
                '-i',
                cert_file_path
            ]
        elif sys.platform == 'darwin':
            try:
                subprocess.call([
                    'security',
                    'add-certificate',
                    cert_file_path
                ])
                subprocess.call([
                    'security',
                    'add-trusted-cert',
                    '-p',
                    'ssl',
                    cert_file_path
                ])
            except Exception as e:
                click.echo('Could not add certificate to certificate store')
                sys.exit(1)
        else:
            command = [
                'certutil.exe',
                '-viewstore',
                '-user',
                'root'
            ]

        try:
            subprocess.call(command)
        except Exception as e:
            click.echo('Could not add certificate to certificate store')
            click.echo(e)
            sys.exit(1)

    def place_certificates(self, cert_file_path, cert_file, paths):
        for path in paths:
            shutil.copyfile(cert_file_path, '{}/{}'.format(path, cert_file))

    def _firefox_cert_location(self):
        path = None
        if sys.platform == 'linux' or sys.platform == 'linux2':
            path = os.path.join(
                os.getenv('HOME'),
                '.mozilla/certificates'
            )
        elif sys.platform == 'darwin':
            # Make directory if it doesn't exist
            path = os.path.join(
                os.getenv('HOME'),
                '/Library/Application Support/Mozilla/Certificates'
            )
        elif sys.platform == 'win32':
            path = os.path.join(
                os.getenv('USERPROFILE'),
                '\\AppData\\Local\\Mozilla\\Certificates'
            )
        if path is not None:
            if not os.path.isdir(path):
                os.makedirs(path)
        return path

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
        config_exists = os.path.isfile('{}/{}'.format(self.CONFIG_FOLDER_PATH,
                                                      self.CONFIG_FILE))

        if not config_dir_exists or not config_exists:
            msg = self.MISSING_CONFIGURATION.format(self.CONFIG_FOLDER_PATH,
                                                    self.CONFIG_FILE)
            click.echo(msg)
            sys.exit(1)

    def get_config(self):
        """Gets config from file.

        Returns:
            config
        """
        self.check_for_config()
        config = ConfigParser()
        config.read('{}/{}'.format(self.CONFIG_FOLDER_PATH, self.CONFIG_FILE))
        return config

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
            openssl_format = serialization.PrivateFormat.TraditionalOpenSSL
            no_encyption = serialization.NoEncryption()
            key_data = key.private_bytes(encoding=serialization.Encoding.PEM,
                                         format=openssl_format,
                                         encryption_algorithm=no_encyption)
            user_fingerprint = self.config.get(self.server, 'fingerprint')
            encrypted_key = self.encrypt(key_data, user_fingerprint)
            user_email = self.config.get(self.server, 'email')
            click.echo('Encrypting file to {}'.format(user_email))
            with open(key_path, 'w') as f:
                f.write(str(encrypted_key))
        return key

    def generate_csr(self, key):
        country = self.config.get(self.server, 'country')
        state = self.config.get(self.server, 'state')
        locality = self.config.get(self.server, 'locality')
        organization_name = self.config.get(self.server, 'organization_name')
        common_name = self.config.get(self.server, 'common_name')
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName(self.server),
                x509.DNSName('*.{}'.format(self.server)),
            ]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())
        return csr

    def sign_and_send_to_server(self, csr):
        server_fingerprint = self.config.get(self.server, 'server_fingerprint')
        csr_public_bytes = csr.public_bytes(serialization.Encoding.PEM)
        click.echo('Signing CSR for verification on server...')
        signature = self.gpg.sign(
            csr_public_bytes,
            keyid=self.config.get(self.server, 'fingerprint'),
            detach=True,
            clearsign=True
        )
        payload = {
            'csr': str(csr_public_bytes.decode('utf-8')),
            'signature': str(signature),
            'lifetime': '18',  # Currently locked 18 hours
            'host': self.config.get(self.server, 'host'),
            'type': 'CREATE_CERTIFICATE'
        }
        server_url = self.config.get(self.server, 'url')
        r = requests.post(server_url, json=payload)
        response = r.json()
        if response.get('error', False):
            click.echo(response.get('msg'))
            sys.exit(1)
        return str(response['data'])


@click.command()
@click.option('--server', '-s')
@click.option('--version', '-v',
              is_flag=True, callback=MutualTLS.print_version,
              expose_value=False, is_eager=True)
def main(server=None):
    mtls = MutualTLS(server)
    mtls.run()


if __name__ == '__main__':
    main()
