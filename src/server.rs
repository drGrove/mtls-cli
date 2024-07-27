use std::path::PathBuf;
use std::process;

use configparser::ini::{Ini, WriteOptions};

use crate::cli::{Cli,ServerSubCommands};


pub struct ServerCommand {}

impl ServerCommand {
    pub fn handle(command: &ServerSubCommands, cli: &Cli) {
        let mut config = Ini::new();
        let mut controller;
        if let Some(config_path) = cli.config_path.as_ref() {
            if config_path.exists() {
                let _ = config.load(config_path);
                controller = ServerController::new(&mut config, config_path.to_path_buf());
            } else {
                println!("No config to load");
                return
            }
            match command {
                ServerSubCommands::Add { url, name } => controller.add(url.to_string(), name.to_string()),
                ServerSubCommands::List {} => controller.list(),
                ServerSubCommands::Remove { name } => controller.remove(name.to_string()),
            }
        } else {
            eprintln!("Could not get config_path: {}", cli.config_path.as_ref().expect("Config Path should be set").to_str().unwrap_or("Invalid UTF-8 path").to_string());
            return
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
