# Mutual TLS Client (mtls) #

[![Known Vulnerabilities](https://snyk.io/test/github/drGrove/mtls-cli/badge.svg)](https://snyk.io/test/github/drGrove/mtls-cli)
[![CircleCI](https://circleci.com/gh/drGrove/mtls-cli/tree/master.svg?style=svg)](https://circleci.com/gh/drGrove/mtls-cli/tree/master)
![PyPI](https://img.shields.io/pypi/v/mtls?color=green)
![AUR version](https://img.shields.io/aur/version/mtls)

## Runtime Dependencies ##

* python >= 3.7
* gnupg2
* libnss3 (linux/windows)
* security (MacOS)

## Overview ##

A mutual TLS (mTLS) system for authenticating users to services that need to be on the internet, but should only be
accessible to users that specifically need it. This should be used as a initial security measure on top of normal login
to handle multi-factor authentication.

The client generates a Certificate Signing Request (CSR) and use web of trust to ensure user has authentication to
recieve a short-lived client certificate. Short-lived certificates have a default timeout of 18 hours, but can be
expanded per need.

This system uses some of the base NSS primitives found in base tools for the associted operating systems.

This project currently works in the following OSes:

* Linux (Arch/Debian/Ubuntu tested)
* MacOS

This project is based on the whitepapers for [Beyond Corp](https://www.beyondcorp.com/), which is Googles Zero Trust
Security Model.

## Background ##

### What is Mutual TLS? ###

Mutual TLS is a sub-category of [Mutual Authentication](https://en.wikipedia.org/wiki/Mutual_authentication), where the
client and server, or server and server are verifying the identity of one another to ensure that both parties should be
allowed to access the requested information.

### What is this Good For? ###

Creating services that inheritely trust no one unless specifically authorized.  This provides the basis for a zero
trust, multi-factor authentication scheme while also timeboxing access to the requested service in case of compromise or
loss of access keys.

### What parts of my system are affected by this? ###

This uses 2 certificate stores within your system. The primary is held at `~/.pki/nssdb` which is the default nssdb that
most of the OS trusts. A secondary nssdb will exist within `.mozilla/firefox/` which is a firefox specific nssdb and is
required to interface with any mozilla products. There are slightly different commands that are required depending on
the operating system.

To list certificates via the commandline on Linux:
`certutil -L -d ~/.pki/nssdb`

To verify a certificate via the commandline on Linux:
`certutil -V -u C -d ~/.pki/nssdb -n '<Server> - <name>@<host>'`

A Root certificate is required for this. The CLI will by default pull the Root CA and install it into your Trust Store
as a Trusted Root Certificate.

## Installation ##

### Building From Source ###

```shell
$ git clone https://github.com/drGrove/mtls-cli
$ make build
# If you'd like to install directly into ~/.local/bin you can also use
$ make install
```

### Using The Latest Release ###

There are signed binaries that are shipped along with each release. To use a binary you can do the following:

```shell
$ VERSION=<version> (ex. VERSION=v0.8.0)
$ wget https://github.com/drGrove/mtls-cli/releases/download/$VERSION/mtls-$VERSION.tar.gz
$ tar zxvf mtls-$VERSION.tar.gz
$ cd mtls
$ sha256sum mtls && cat mtls.sha256sum
$ gpg --recv-keys C92FE5A3FBD58DD3EC5AA26BB10116B8193F2DBD
$ gpg --verify --trust-model always mtls.sig
# From there you can install the binary wherever you'd like in your path
```

## Configuration ##

Configuring mtls is done via a `config.ini`. There is an example in the repo [here](config.ini.example).

You'll need a similar base configuration:

```ini
[DEFAULT]
name=John Doe
email=johndoe@example.com
; PGP Fingerprint
fingerprint=XXXXXXXX
country=US
state=CA
locality=Mountain View
organization=myhost
```

Then for each server you'd like to connect to you can create a section for that service.

```ini
[myserver]
email=johndoe@myserver.com
url=https://certauth.myserver.com
```

The `url` should match the base URL of the Certificate Authority you'll connect to. This will allow `mtls` to make the
requests to generate your client certificate.

## Usage ##

Once configured and provided access by a Certificate Authority Administrator you will be able to begin creating
certificates for yourself. By default the lifetime of your certificate is 18 hours. But Certificate Authorities are able
to set their own minimum and maximum lifetime. Speak to a certificate authority administrator about their settings.

### Creating A Certificate ###

```shell
$ mtls -s myserver certificate create
```

### Revoking A Certificate ###

If you're certificate has become compromised you can revoke your certificate prior to it's expiration. Certificate
Authority Administrators can also expire certificates if they feel that you've been compromised or if they belive you
should no longer have access to the services.

You have a few options as far a certificate revoke goes.

#### By Serial Number ####

```shell
$ mtls -s myserver certificate revoke --serial <Certificate Serial Number>
```

#### By Certificate Name ####

To get a certificate name, it will follow the following convention: `ISSUER - USER@HOSTNAME`. On the first connection to
a Certificate Authority, you're `~/.config/mtls/config.ini` for a particular server will be updated to provide the
issuer name as found in the Root CA Certificate. You can also find this by running `certutil -L -d ~/.pki/nssdb` or
viewing the certificate in chrome or firefox

```shell
$ mtls -s myserver certicate revoke --name <name>
```

### By Fingerprint ####

NOTE: This will revoke all certificates related to a particular fingerprint

```shell
$ mtls -s myserver certificate revoke --fingerprint <fingerprint>
```

## Administration ##

Administration of the `mtls` can be done via the CLI as well. Administrators can add and remove users as they see fit
but currently an administator needs to be removed individually from both trust stores.

### Users ###

#### Adding Users ####

##### By Fingerprint #####

```shell
$ mtls -s myserver user add --fingeprint FINGERPRINT
```

##### By Email #####

This will poll pgp.mit.edu by default and return a list of PGP keys if more than 1 valid PGP key is returned. You can
query any keyserver via the `--keyserver KEYSERVER_URL` flag

```shell
$ mtls -s myserver user add --email johndoe@example.com
```

#### Removing Users ####

##### By Fingerprint #####

```shell
$ mtls -s myserver user remove --fingeprint FINGERPRINT
```

##### By Email #####

This will poll pgp.mit.edu by default and return a list of PGP keys if more than 1 valid PGP key is returned. You can
query any keyserver via the `--keyserver KEYSERVER_URL` flag

```shell
$ mtls -s myserver user remove --email johndoe@example.com
```

### Administrators ###

#### Adding Admins ####

##### By Fingerprint #####

```shell
$ mtls -s myserver user add --fingeprint FINGERPRINT --admin
```

##### By Email #####

This will poll pgp.mit.edu by default and return a list of PGP keys if more than 1 valid PGP key is returned. You can
query any keyserver via the `--keyserver KEYSERVER_URL` flag

```shell
$ mtls -s myserver user add --email johndoe@example.com --admin
```

#### Removing Users ####

##### By Fingerprint #####

```shell
$ mtls -s myserver user remove --fingeprint FINGERPRINT --admin
```

##### By Email #####

This will poll pgp.mit.edu by default and return a list of PGP keys if more than 1 valid PGP key is returned. You can
query any keyserver via the `--keyserver KEYSERVER_URL` flag

```shell
$ mtls -s myserver user remove --email johndoe@example.com --admin
```

## Development ##

### Dependencies ###

* make
* pip
* pipenv
* gnupg
* libnss (certutil/pk12util on linux/windows, security on MacOS)

### Getting Started ###

To begin development run the following commands:

```shell
make setup
mkdir ~/.config/mtls
cp config.ini.example config.ini
```

NOTE: You will need to add a server to communicate with. The URL must have a scheme.

You can run without compiling by using:

```shell
make run SERVICE=myservice
```

To build a binary:

```shell
make build
```

NOTE: This will output to an mtls folder within the root of the project. This folder has been gitignored and only
artifacts of the build belong in this directory
