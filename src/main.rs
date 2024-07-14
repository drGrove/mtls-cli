mod certificate;
mod cli;
mod init;
mod server;
mod util;

use std::env;
use std::path::PathBuf;

use clap::{CommandFactory, Parser};

use cli::{Cli, BaseCommands};
use crate::init::InitCommand;
use crate::certificate::CertificateCommand;
use crate::server::ServerCommand;
use crate::util::ensure_directory_exists;


fn main() {
    let mut cli = Cli::parse();
    let cmd = Cli::command();

    let default_config_path = env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let mut home = dirs::home_dir().expect("Unable to find HOME directory");
            home.push(".config");
            home
        })
        .join("mtls/config.ini");

    cli.config_path.get_or_insert_with(|| PathBuf::from(default_config_path));
    let config_dir = cli
        .config_path
        .as_ref().expect("Config Path missing")
        .parent().expect("Config path parent to exist");
    let _ = ensure_directory_exists(config_dir);
    match &cli.command {
        BaseCommands::Config {} => {
            println!("{} config", cmd.get_name());
        },
        BaseCommands::Init {} => InitCommand::handle(&cli),
        BaseCommands::Certificate { command } =>  CertificateCommand::handle(&command, &cli),
        BaseCommands::Server { command } => ServerCommand::handle(&command, &cli)
    }
}
