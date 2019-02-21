"""mtls (Mutual TLS) - A cli for creating short-lived client certiicates."""

import os
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
        self.config = self.get_config()
        self.server = server
        self.server_in_config()
        self.openssl_format = serialization.PrivateFormat.TraditionalOpenSSL
        self.no_encyption = serialization.NoEncryption()
        self.friendly_name = "{org} - {cn}@{host}".format(
            org=self.config.get(
                self.server,
                'organization_name'
            ),
            cn=self.config.get(self.server, 'common_name'),
            host=self.config.get(self.server, 'host')
        )
        pfx_path = '{base_path}/{server}/{server}.pfx'.format(
            base_path=self.CONFIG_FOLDER_PATH,
            server=self.server
        )
        self.pfx_path = pfx_path
        ca_cert_file_path = '{base_path}/{server}/{server}.ca.pem'.format(
            base_path=self.CONFIG_FOLDER_PATH,
            server=self.server
        )
        self.ca_cert_path = ca_cert_file_path
        cert_file_path = '{base_path}/{server}/{server}.pem'.format(
            base_path=self.CONFIG_FOLDER_PATH,
            server=self.server
        )
        self.cert_file_path = cert_file_path

    def run(self):
        self._create_db()
        if not self._has_root_cert():
            click.echo('Root Certificate is required for validation.')
            click.echo('Please run `mtls --add-root-cert` for instructions')
            sys.exit(1)

        valid = self.check_valid_cert()
        if valid is True:
            click.echo("Reusing valid certificate")
            sys.exit(0)
        csr = self.get_csr()
        key = self.get_key_or_generate()
        if csr is None:
            csr = self.generate_csr(key)
        cert_str = self.sign_and_send_to_server(csr)
        if cert_str is None:
            click.echo('Could not retrieve certificate from server')
            sys.exit(1)
        cert = self.convert_to_cert(cert_str)
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
        with open(self.cert_file_path, 'wb') as f:
            f.write(p12.export(passphrase=bytes(pwd, 'utf-8')))
        self.update_cert_storage(
            self.cert_file_path,
            pwd,
            self.ca_cert_file_path
        )

    def _has_root_cert(self):
        if self.check_valid_cert(
            name=self.config.get(self.server, 'issuer_name'),
            usage='TC'
        ):
            return True
        return False

    def delete_cert_by_name(self, name):
        if sys.platform == 'darwin':
            return None
        paths = _get_certdb_paths()
        for path in paths:
            cmd = [
                self._get_base_cert_command(),
                '-D',
                '-d',
                path,
                '-n',
                name
            ]

            try:
                output = self._run_cmd(cmd)
            except Exception as e:
                click.echo("Error")
                click.echo(e)

    def check_valid_cert(self, name=self.friendly_name, usage='C'):
        if sys.platform == 'darwin':
            return None
        paths = self._get_certdb_paths()
        is_valid = True
        for path in paths:
            cmd = [
                self._get_base_cert_command(),
                '-V',
                '-u',
                usage,
                '-d',
                path,
                '-n',
                name
            ]

            output = self._run_cmd(cmd, capture_output=True)
            if "certificate is invalid" in str(output.stdout, 'UTF-8'):
                self.delete_cert_by_name(self.friendly_name)
                is_valid = False

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
            click.echo('Failed to generate appropriate password.')
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
            print('Failure to load PEM x509 Certificate: {}'.format(e))

    def _run_cmd(self, args, capture_output=False):
        if capture_output:
            return subprocess.run(args, capture_output=capture_output)
        return subprocess.call(args)

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
                        self.config.get(self.server, 'host')
                    ])
                except Exception as e:
                    cse = 'Could not add certificate to certificate store'
                    click.echo(cse)
                    click.echo(e)
        elif sys.platform == 'darwin':
            try:
                self._run_cmd([
                    'security',
                    'add-certificate',
                    cert_file_path
                ])
            except Exception as e:
                click.echo(
                    'Could not add certificate to certificate store'
                )
        else:
            try:
                self._run_cmd([
                    'certutil.exe',
                    '-viewstore',
                    '-user',
                    'root'
                ])
            except Exception as e:
                click.echo('Could not add certificate to certificate store')
                click.echo(e)

    def _create_db(self):
        path = self._primary_certdb_location()
        if sys.platform == 'linux' or sys.platform == 'linux2':
            if not os.path.isdir(path):
                os.makedirs(path)
                # This assumes that you're using an encrypted hard drive
                # Othewise we need to look into a way to allow user input
                # Probably swapping subprocess.call with subprocess.popen so
                # that users can manually enter passwords
                click.echo("Making nssdb at {}".format(path))
                subprocess.call([
                    "certutil",
                    "-d",
                    path,
                    "-N",
                    "--empty-password"
                ])

    def _get_certdb_paths(self):
        return [
            self._primary_certdb_location(),
            self._firefox_certdb_location()
        ]

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
                '/Library/Application\\ Support/Firefox'
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

    @staticmethod
    def add_root_certificate(ctx, param, value):
        """Adds the servers root certificate to the users trust store."""
        click.echo("Root certificates need to be manually added.")
        click.echo("Example commands for your OS will be printed below")
        click.echo(
            "NOTE: These will need to be modified to have you Servers Name"
        )
        if sys.platform == 'linux' or sys.platform == 'linux2':
            distribution = distro.linux_distribution(
                full_distribution_name=False
            )
            distro_name = distribution[0]
            distro_version = distribution[1]
            click.echo('curl https://serverurl.tld/ca > Server.pem')
            if distro_name == 'centos':
                major_number = int(distro_version.split('.')[0])
                if major_number >= 6:
                    click.echo('yum install ca-certificate')
                    click.echo('update-ca-trust force-enable')
                    click.echo(
                        'cp Server.pem /etc/pki/ca-trust/source/anchors/'
                    )
                    click.echo('update-ca-trust extract')
                else:
                    click.echo(
                        'cat Serer.pem >> /etc/pki/tls/certs/ca-bundle.crt'
                    )
            elif distro_name == 'ubuntu' or distro_name == 'debian':
                cmd = 'sudo cp Server.pem '
                cmd += '/usr/local/share/ca-certificates/Server.pem'
                click.echo(cmd)
                click.echo("sudo update-ca-certificates")
            elif distro_name == 'arch':
                click.echo('sudo cp Server.pem ' +
                           '/usr/local/share/ca-certificates/Server.pem')
                click.echo('sudo update-ca-trust')
            else:
                click.echo('Your distribution is not supported.')
                sys.exit(1)
        elif sys.platform == 'darwin':
            click.echo('curl https://serverurl.tld/ca > Server.pem')
            click.echo('sudo security add-trusted-cert -d -r trustRoot -k ' +
                       '/Library/Keychains/System.keychain ~/Server.pem')
        elif sys.platform == 'win32':
            click.echo('curl https://serverurl.tld/ca > Server.pem')
            click.echo('certutil -addstore -f "ROOT" Server.pem')
        else:
            click.echo('Your OS is not supported.')
            sys.exit(1)

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
        ])).sign(key, hashes.SHA256(), default_backend())
        csr_fname = '{}.csr.asc'.format(self.server)
        with open(
            '{}/{}'.format(self.CONFIG_FOLDER_PATH, csr_fname),
            'wb'
        ) as f:
            enc_csr = self.encrypt(
                csr.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                self.config.get(self.server, 'fingerprint')
            )
            f.write(bytes(str(enc_csr), 'utf-8'))
        return csr

    def _get_path(self, path):
        if not os.path.isabs(path):
            return os.path.abspath(
                os.path.join(
                    self.CONFIG_FOLDER_PATH,
                    path
                )
            )

    def _get_base_cert_command(self):
        cmd = None
        if sys.platform == 'linux' or sys.platform == 'linux2':
            cmd = 'certutil'
        elif sys.platform == 'darwin':
            cmd = 'security'
        elif sys.platform == 'win32':
            cmd = 'certutil.exe'

        if cmd is None:
            click.echo('You do not have a supported operating system')
            sys.exit(1)

        return cmd

    def send_request(self, url, payload, verify=True, attempts=0):
        if attempts == 4:
            raise TooManyAttemptsError()
        try:
            r = requests.post(
                url,
                json=payload,
                verify=verify
            )
        except requests.exceptions.SSLError:
            ca_location = self.config.get(self.server, 'ca_location')
            ca_path = self._get_path(ca_location)
            if os.path.isfile(ca_path):
                verify = ca_path
            else:
                verify = False
                click.echo('Disabling SSL Verification')
                click.echo('Please get a Certificate from your Root CA')
            if attempts > 1:
                verify = False
            r = self.send_request(
                url,
                payload,
                verify=verify,
                attempts=(attempts + 1))
        return r

    def sign_and_send_to_server(self, csr):
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
            'lifetime': '18',  # Currently locked 18 hours
            'host': self.config.get(self.server, 'host'),
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
@click.option('--add-root-cert',
              is_flag=True, callback=MutualTLS.add_root_certificate,
              expose_value=False, is_eager=True)
def main(server=None):
    mtls = MutualTLS(server)
    mtls.run()


if __name__ == '__main__':
    main()
