use std::process;

use clap::CommandFactory;
use configparser::ini::{Ini, WriteOptions};

use crate::cli::{Cli,ServerSubCommands};
use crate::util::inquire;


pub struct ServerCommand {}

impl ServerCommand {
    pub fn add(_cli: &Cli) {
        let cmd = Cli::command();
        println!("{} server add", cmd.get_name())
    }

    pub fn list(_cli: &Cli) {
        let cmd = Cli::command();
        println!("{} server list", cmd.get_name())
    }

    pub fn remove(_cli: &Cli) {
        let cmd = Cli::command();
        println!("{} server list", cmd.get_name())
    }

    pub fn handle(command: &ServerSubCommands, cli: &Cli) {
        match command {
            ServerSubCommands::Add {} => ServerCommand::add(cli),
            ServerSubCommands::List {} => ServerCommand::list(cli),
            ServerSubCommands::Remove {} => ServerCommand::remove(cli),
        }
    }
}

/*
pub struct ServerController {}

impl ServerController {
    pub fn add(config: Ini, name: String, url: String) {
        if name == "" {
            eprintln!("Server name cannot be empty");
            process::exit(1)
        }
        if name.contains(char::is_whitespace) {
            eprintln!("Server name cannot contain a space");
            process::exit(1)
        }
        // config.set(&name, "url", Some(url));
        // let write_options = WriteOptions::new_with_params(true, 2, 1);
        // let _ = config.pretty_write(config_path, &write_options);
    }
}
*/
