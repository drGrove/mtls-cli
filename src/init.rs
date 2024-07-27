use std::process;

use clap::CommandFactory;
use configparser::ini::{Ini, WriteOptions};

use crate::cli::Cli;
use crate::util::{inquire, get_gpg_keys_for_email, print_key_info};


pub struct InitCommand {}

impl InitCommand {
    pub fn handle(cli: &Cli) {
        let cmd = Cli::command();
        let mut config = Ini::new();
        println!("Welcome to {}!", cmd.get_name());
        let name = inquire("What's your name?".to_string());
        let email = inquire("What's your email?".to_string());
        let email_vec: Vec<String> = email
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let keys = match get_gpg_keys_for_email(email_vec) {
            Ok(keys) => keys,
            Err(e) => {
                eprintln!("Error: {}", e);
                return
            }
        };
        for (index, key) in keys.iter().enumerate() {
            println!("Key {}:", index + 1);
            let _ = print_key_info(key);
            println!();
        }
        let position = inquire("Which key would you like to use?".to_string()).parse::<usize>().unwrap();
        let fingerprint;
        if let Some(key) = keys.get(position-1) {
            fingerprint = key.fingerprint().unwrap_or("?");
        } else {
            eprintln!("Error: No key found at position {}", position -1);
            return
        }

        if let Some(config_path) = cli.config_path.as_ref() {
            if config_path.exists() {
                let _ = config.load(config_path);
                println!("Loading config file: {}", config_path.display());
            } else {
                println!("No config to load")
            }
        } else {
            eprintln!("Could not get config_path: {}", cli.config_path.as_ref().expect("Config Path should be set").to_str().unwrap_or("Invalid UTF-8 path").to_string());
            return
        }
        config.set("DEFAULT", "name", Some(name));
        config.set("DEFAULT", "email", Some(email));
        config.set("DEFAULT", "fingerprint", Some(fingerprint.to_string()));

        let write_options = WriteOptions::new_with_params(true, 2, 1);
        if let Some(config_path) = cli.config_path.as_ref() {
            println!("Writing config to: {}", config_path.display());
            let _ = config.pretty_write(config_path, &write_options);
        } else {
            eprintln!("Failed to write to config file");
            process::exit(1);
        }
        loop {
            let add_server_inq = inquire("Would you like to add a server? (y/N) ".to_string());
            if ! add_server_inq.to_lowercase().starts_with("y") {
                break;
            }

            let server_name = inquire("Nickname for server: ".to_string());
            let prompt = "What is the URL of the Certificate Authority? (e.g. https://certauth.example.com)";
            let url = inquire(prompt.to_string());
            config.set(&server_name, "url", Some(url));
            if let Some(config_path) = cli.config_path.as_ref() {
                println!("Writing config to: {}", config_path.display());
                let _ = config.pretty_write(config_path, &write_options);
            } else {
                eprintln!("Failed to write to config file");
                process::exit(1);
            }
        }
    }
}
