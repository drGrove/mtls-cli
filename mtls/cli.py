#!/usr/bin/env python3
import os
import pathlib
import sys
from configparser import ConfigParser
from datetime import datetime

import click
import gnupg

from .mtls import MutualTLS
from . import __version__


HELP_TEXT = (
    "mtls is a PGP Web of Trust based SSL Client Certificate "
    "generation tool based on Googles Beyond Corp Zero Trust "
    f"Authentication. Version {__version__}"
)

ALLOWED_KEYS = [
    "name",
    "email",
    "host",
    "fingerprint",
    "country",
    "state",
    "locality",
    "common_name",
    "organization_name",
    "lifetime",
    "url",
]

HOME = os.environ.get("XDG_CONFIG_HOME", os.environ.get("HOME") + ".config/")


def initial_setup(config_path):
    """Run the user through inital setup."""
    click.secho("Welcome to MTLS!")
    name = input("What's you name? ")
    email = input("What's your email? ")
    gpg_keys = get_gpg_keys_for_email(email)
    for idx, key in enumerate(gpg_keys):
        created = datetime.utcfromtimestamp(int(key.get("date"))).strftime(
            "%Y-%m-%d"
        )
        try:
            expires = datetime.utcfromtimestamp(
                int(key.get("expires"))
            ).strftime("%Y-%m-%d")
        except Exception:
            expires = "Never"
        click.secho(
            f"{idx + 1}) {key.get('keyid')} - Created: {created} Expires: {expires}"
        )
    if len(gpg_keys) > 0:
        key = int(input("Which key would you like to use? ")) - 1
        if key < 0 or key >= len(gpg_keys):
            click.secho("Invalid input, bailing", fg="red")
            sys.exit(1)
        fingerprint = gpg_keys[key].get("fingerprint")
    else:
        click.secho("No PGP keys found", fg="red")
        fingerprint = ""
    config = ConfigParser()
    config.read(config_path)
    config["DEFAULT"] = {
        "name": name,
        "email": email,
        "fingerprint": fingerprint,
    }

    # Taken from https://stackoverflow.com/a/12517490
    if not os.path.exists(os.path.dirname(config_path)):
        try:
            os.makedirs(os.path.dirname(config_path))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

    with open(config_path, "w") as config_file:
        config.write(config_file)


def get_gpg_keys_for_email(email):
    """Given an email address, return all local keys."""
    gpg = gnupg.GPG()
    gpg.encoding = "utf-8"
    keys = gpg.list_keys()
    out_keys = []
    for key in keys:
        for uid in key.get("uids"):
            if email in uid:
                out_keys.append(key)
    return out_keys


@click.group(help=HELP_TEXT)
@click.version_option(__version__, message="%(version)s")
@click.option(
    "--server", "-s", type=str, help="Server to run command against."
)
@click.option(
    "--config",
    "-c",
    type=click.Path(),
    default=os.path.join(HOME, "/mtls/config.ini"),
    help=f"config file. [{HOME}/mtls/config.ini]",
)
@click.option("--gpg-password", type=str, hidden=True)
@click.pass_context
def cli(ctx, server, config, gpg_password):
    options = {"config": config, "gpg_password": gpg_password}
    if server is not None:
        ctx.obj = MutualTLS(server, options)
    else:
        ctx.obj = {"config_path": config, "server": server or "DEFAULT"}
    if sys.platform == "win32" or sys.platform == "cygwin":
        click.secho("Your platform is not currently supported", fg="red")


@cli.command(help="Initialize")
@click.pass_context
def init(ctx):
    initial_setup(ctx.obj.get("config_path"))
    while True:
        add_new_server = (
            input("Would you like to add a server? (y/n) ").lower().strip()
        )
        if add_new_server[:1] == "y":
            server_name = input("Nickname for server: ")
            ctx.invoke(add_server, name=server_name)
        else:
            break


@cli.command(help="Manage config")
@click.argument("key")
@click.argument("value")
@click.pass_context
def config(ctx, key, value):
    AK_MSG = f"Your key must be in the allowed keys, available options are: {ALLOWED_KEYS}"
    # Deal with not actually instanting the MutualTLS class.
    try:
        server = ctx.obj.server or "DEFAULT"
        config_path = ctx.obj.config_file_path
    except Exception as err:
        server = ctx.obj["server"]
        config_path = ctx.obj["config_path"]

    if not os.path.exists(config_path):
        config = ConfigParser()
        config["DEFAULT"] = {}
        config_dir = pathlib.Path(config_path).parent
        config_dir.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as config_file:
            config.write(config_file)

    if key not in ALLOWED_KEYS:
        click.secho(AK_MSG, fg="red")
        sys.exit(1)
    if server == "DEFAULT" and key == "url":
        click.secho(
            "url is not a valid config when no server is set", fg="red"
        )
        sys.exit(1)
    config = ConfigParser()
    config.read(config_path)
    config.set(server, key, value)
    with open(config_path, "w") as config_file:
        config.write(config_file)


@click.group(help="Manage Servers")
@click.pass_context
def server(ctx):
    pass


@server.command("add", help="Add a server")
@click.argument("name")
@click.pass_context
def add_server(ctx, name):
    if name is None or name == "":
        click.secho("Server name cannot be empty", fg="red")
    if " " in name:
        click.secho("Server name cannot have space in it.", fg="red")
        sys.exit(1)
    config_path = ctx.obj["config_path"]
    value = click.prompt(
        "What is the url of the Certificate Authority? (ie. https://certauth.example.com)"
    )
    config = ConfigParser()
    config.read(config_path)
    config.add_section(name)
    config.set(name, "url", value)
    with open(config_path, "w") as config_file:
        config.write(config_file)


@server.command("remove", help="Remove a server")
@click.argument("name")
@click.pass_context
def remove_server(ctx, name):
    if name is None or name == "":
        click.secho("Server name cannot be empty", fg="red")
    if " " in name:
        click.secho("Server name cannot have space in it.", fg="red")
        sys.exit(1)
    config_path = ctx.obj["config_path"]
    config = ConfigParser()
    config.read(config_path)
    config.remove_section(name)
    with open(config_path, "w") as config_file:
        config.write(config_file)


@click.group(help="Manage Certificates")
@click.pass_context
def certificate(ctx):
    pass


@certificate.command(
    "create", help="Create a Client Certificate for a given server."
)
@click.option(
    "--output",
    "-o",
    help="""
        Output the pfx file to a location.
        File will not be added to Certificate Store.
    """,
    type=click.Path(exists=False),
)
@click.option(
    "--friendly-name", help="The friendly name of the certificate", type=str
)
@click.option(
    "--user-email", help="The users email for the certificate", type=str
)
@click.option(
    "--organization", "-org", help="The users organization", type=str
)
@click.option(
    "--common-name", "-c", help="The common name for the certificate", type=str
)
@click.pass_context
def create_certificate(
    ctx, output, friendly_name, user_email, organization, common_name
):
    options = {}
    if not isinstance(ctx.obj, MutualTLS):
        click.secho("A server was not provided.", fg="red")
        sys.exit(1)
    if friendly_name:
        options.update(friendly_name=friendly_name)
    if user_email:
        if not common_name:
            click.secho("Must override common name if overriding email")
            sys.exit(1)
        options.update(email=user_email)
    if organization:
        options.update(organization=organization)
    if common_name:
        options.update(common_name=common_name)
    ctx.obj.get_crl(False)
    ctx.obj.set_user_options(options)
    ctx.obj.create_cert(output)


@certificate.command("revoke", help="Revoke a certificate for a given server.")
@click.option("--fingerprint", "-f", default=None, help="User PGP Fingerprint")
@click.option(
    "--serial-number", default=None, help="Serial Number of certificate"
)
@click.option(
    "--name", "-n", default=None, help="The common name on the certificate."
)
@click.pass_context
def revoke_certificate(ctx, fingerprint, serial_number, name):
    if not isinstance(ctx.obj, MutualTLS):
        click.secho("A server was not provided.", fg="red")
        sys.exit(1)
    ctx.obj.revoke_cert(fingerprint, serial_number, name)


@certificate.command("crl", help="Get the CRL for a given server")
@click.option(
    "--output/--no-output",
    "-o/-no",
    is_flag=True,
    default=True,
    help=f"Output to stdout. Otherwise this will write to {HOME}/mtls/<server>/crl.pem",
)
@click.pass_context
def get_crl(ctx, output):
    if not isinstance(ctx.obj, MutualTLS):
        click.secho("A server was not provided.", fg="red")
        sys.exit(1)
    ctx.obj.get_crl(output)


@click.group(help="Manage Users")
@click.pass_context
def user(ctx):
    pass


@user.command("add", help="Add a user (Admin Required).")
@click.option(
    "--admin", is_flag=True, default=False, help="Is the user an admin"
)
@click.option("--fingerprint", "-f", default=None, help="User PGP Fingerprint")
@click.option(
    "--email",
    "-e",
    default=None,
    help="User email. This will grab the users fingerprint from your local "
    + "trust store",
)
@click.option(
    "--keyserver",
    default=None,
    help="Keyserver for searching by email. Defaults to pgp.mit.edu",
)
@click.pass_context
def add_user(ctx, admin, fingerprint, email, keyserver):
    if not isinstance(ctx.obj, MutualTLS):
        click.secho("A server was not provided.", fg="red")
        sys.exit(1)
    if fingerprint is None and email is None:
        click.echo("A fingerprint or email must be provided")
        sys.exit(1)
    if email is not None:
        fingerprint = handle_email(ctx, email, keyserver)
    ctx.obj.add_user(fingerprint, admin)


@user.command("remove", help="Remove a user (Admin Required).")
@click.option(
    "--admin", is_flag=True, default=False, help="Is the user an admin"
)
@click.option("--fingerprint", "-f", default=None, help="User PGP Fingerprint")
@click.option(
    "--email",
    "-e",
    default=None,
    help="User email. This will grab the users fingerprint from your local "
    + "trust store",
)
@click.option(
    "--keyserver",
    default=None,
    help="Keyserver for searching by email. Defaults to pgp.mit.edu",
)
@click.pass_context
def remove_user(ctx, admin, fingerprint, email, keyserver):
    if not isinstance(ctx.obj, MutualTLS):
        click.secho("A server was not provided.", fg="red")
        sys.exit(1)
    if fingerprint is None and email is None:
        click.echo("A fingerprint or email must be provided")
        sys.exit(1)
    if email is not None:
        fingerprint = handle_email(ctx, email, keyserver)

    ctx.obj.remove_user(fingerprint, admin)


def handle_email(ctx, email, keyserver=None):
    if keyserver:
        search_res = ctx.obj.gpg.search_keys(email, keyserver=keyserver)
    else:
        search_res = ctx.obj.gpg.search_keys(email)
    now = str(int(datetime.now().timestamp()))
    non_expired = []
    for res in search_res:
        if res["expires"] == "" or res["expires"] > now:
            non_expired.append(res)
    if len(non_expired) == 0:
        click.secho("A fingerprint with the key could not be found.")
        sys.exit(1)
    if len(non_expired) == 1:
        return non_expired[0]["keyid"]
    for idx, res in enumerate(non_expired):
        click.echo(
            "{idx}) {fingerprint} {uid} - Created: {created}".format(
                idx=idx,
                fingerprint=res["keyid"],
                uid=res["uids"][0],
                created=datetime.utcfromtimestamp(int(res["date"])).strftime(
                    "%m/%d/%Y %H:%M:%S"
                ),
            )
        )
    num = len(non_expired)
    try:
        value = int(input("Please select a key to add: "))
        if value > num:
            click.secho("Invalid number, exiting")
            sys.exit(1)
    except Exception:
        click.secho("Invalid number, exiting")
        sys.exit(1)
    return non_expired[value]["keyid"]


# Bind the subcommands to the cli
cli.add_command(certificate)
cli.add_command(user)
cli.add_command(server)
