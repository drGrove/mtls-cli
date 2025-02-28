use std::path::PathBuf;
use lazy_static::lazy_static;
use std::env;

use clap::{Parser, Subcommand};
use xdg;

use crate::util::CONFIG_DIR_PREFIX;

lazy_static! {
    static ref DEFAULT_CONFIG_PATH: PathBuf = {
        xdg::BaseDirectories::with_prefix(CONFIG_DIR_PREFIX)
            .unwrap()
            .place_config_file("config.ini")
            .expect("Failed to place config.ini in the XDG config directory")
    };
}


#[derive(Parser)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION")
)]
pub struct Cli {
    /// Server to run command against
    #[arg(short, long)]
    pub server: Option<String>,
    /// Config file
    #[arg(short='c', long="config", default_value_os_t = DEFAULT_CONFIG_PATH.to_path_buf())]
    pub config_path: PathBuf,

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
        user_email: Option<String>,

        #[arg(long)]
        organization: Option<String>,

        #[arg(long)]
        common_name: Option<String>,
    },
}

