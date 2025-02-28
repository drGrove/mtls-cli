use std::path::PathBuf;
use std::process;

use configparser::ini::{Ini, WriteOptions};

use crate::commands::cli::{Cli,ServerSubCommands};


pub struct ServerCommand {}

impl ServerCommand {
    pub fn handle(command: &ServerSubCommands, cli: &Cli) {
        let mut config = Ini::new();
        let mut controller;
        let config_path: PathBuf = cli.config_path.clone();
        println!("Config path: {}", config_path.display());
        if config_path.exists() {
            let _ = config.load(&config_path);
            controller = ServerController::new(&mut config, config_path);
        } else {
            println!("No config to load");
            return
        }
        match command {
            ServerSubCommands::Add { url, name } => controller.add(url.to_string(), name.to_string()),
            ServerSubCommands::List {} => controller.list(),
            ServerSubCommands::Remove { name } => controller.remove(name.to_string()),
        }
    }
}

pub struct ServerController<'a> {
    config: &'a mut Ini,
    config_path: PathBuf
}

impl<'a> ServerController<'a> {
    fn new(config: &'a mut Ini, config_path: PathBuf) -> ServerController<'a> {
        ServerController {
            config,
            config_path
        }
    }

    fn add(&mut self, name: String, url: String) {
        if name == "" {
            eprintln!("Server name cannot be empty");
            process::exit(1)
        }
        if name.contains(char::is_whitespace) {
            eprintln!("Server name cannot contain a space");
            process::exit(1)
        }
        self.config.set(&name, "url", Some(url));
        let write_options = WriteOptions::new_with_params(true, 2, 2);
        let _ = self.config.pretty_write(self.config_path.clone(), &write_options);
    }

    fn list(&mut self) {
        let sections = self.config.sections();
        for section in sections {
            if section != "default" {
                println!("{}", section);
            }
        }
    }

    fn remove(&mut self, name: String) {
        self.config.remove_section(&name);
        let write_options = WriteOptions::new_with_params(true, 2, 2);
        let _ = self.config.pretty_write(self.config_path.clone(), &write_options);
    }
}
