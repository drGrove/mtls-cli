# Mutual TLS Client (mtls) #

[![Known Vulnerabilities](https://snyk.io/test/github/drGrove/mtls-client/badge.svg)](https://snyk.io/test/github/drGrove/mtls-client)

## Overview ##

A mutual TLS (mTLS) system for authenticating users to services that need to be on the internet, but should only be
accessible to users that specifically need it. This should be used as a initial security measure on top of normal login
to handle multi-factor authentication.

The client generates a Certificate Signing Request (CSR) and use web of trust to ensure user has authentication to
recieve a short-lived client certificate. Short-lived certificates have a default timeout of 18 hours, but can be
expanded per need.

This system uses some of the base NSS primitives found in base tools for the associted operating systems.

This project currently works in the following OSes:

* Linux (Arch/Ubuntu tested)

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

## Development ##

### Dependencies ###

* make
* pipenv
* libnss (certutil/pk12util on linux/windows, security on MacOS)

### Getting Started ###

To begin development run the following commands:

```
shell make setup
mkdir ~/.config/mtls
cp config.ini.example config.ini
```

NOTE: You will need to add a server to communicate with. The URL must have a scheme.

You can run without compiling by using:

```
shell make run SERVICE=myservice
```

To build a binary:

```
shell make build
```
