use crate::cli::{Cli, CertificateSubCommands};
use clap::CommandFactory;

pub struct CertificateCommand {}

impl CertificateCommand {
    pub fn create(_cli: &Cli) {
        let cmd = Cli::command();
        println!("{} certificate add", cmd.get_name())
    }

    pub fn handle(command: &CertificateSubCommands, cli: &Cli) {
        match command {
            CertificateSubCommands::Create {
                output: _,
                friendly_name: _,
                user_email: _,
                organization: _,
                common_name: _
            } => {
                CertificateCommand::create(cli)
            }
        }
    }
}
