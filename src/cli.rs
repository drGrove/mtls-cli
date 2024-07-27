use clap::{Parser, Subcommand};
use std::path::PathBuf;

const CLI_NAME: &str = "mtlsctl";
const CLI_VERSION: &str = "0.1";
const CLI_AUTHOR: &str = "Danny Grove";
const CLI_ABOUT: &str = "Short-lived Client Certificate Creation";

#[derive(Parser)]
#[command(name = CLI_NAME, version = CLI_VERSION, author = CLI_AUTHOR, about = CLI_ABOUT)]
pub struct Cli {
    /// Server to run command against
    #[arg(short, long)]
    pub server: Option<String>,
    /// Config file
    #[arg(short='c', long="config")]
    pub config_path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: BaseCommands,
}

#[derive(Subcommand)]
pub enum BaseCommands {
    Certificate {
        #[command(subcommand)]
        command: CertificateSubCommands,
    },
    Config {

    },
    Init {

    },
    Server {
        #[command(subcommand)]
        command: ServerSubCommands
    }
}

#[derive(Subcommand)]
pub enum ServerSubCommands {
    Add {
        #[arg(short, long, required = true)]
        name: String,
    
        #[arg(short, long, required = true)]
        url: String,
    },
    List {},
    Remove {
        #[arg(short, long, required = true)]
        name: String
    }
}

#[derive(Subcommand, Clone)]
pub enum CertificateSubCommands {
    Create {
        #[arg(short, long)]
        output: Option<PathBuf>,

        #[arg(long)]
        friendly_name: Option<String>,

        #[arg(long)]
        user_email: Option<String>,

        #[arg(long)]
        organization: Option<String>,

        #[arg(long)]
        common_name: Option<String>,
    },
}


