mod commands;
mod util;

use clap::{CommandFactory, Parser};

use crate::commands::cli::{Cli, BaseCommands};
use crate::commands::init::InitCommand;
use crate::commands::certificate::CertificateCommand;
use crate::commands::server::ServerCommand;

fn main() {
    let cli = Cli::parse();
    let cmd = Cli::command();

    match &cli.command {
        BaseCommands::Config {} => {
            println!("{} config", cmd.get_name());
        },
        BaseCommands::Init {} => InitCommand::handle(&cli),
        BaseCommands::Certificate { command } =>  CertificateCommand::handle(&command, &cli),
        BaseCommands::Server { command } => ServerCommand::handle(&command, &cli)
    }
}
