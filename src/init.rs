use std::error::Error;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use clap::CommandFactory;
use configparser::ini::{Ini, WriteOptions};
use gpgme::{Context, KeyListMode, Protocol};

use crate::cli::Cli;
// use crate::server::ServerController;
use crate::util::inquire;


fn get_gpg_keys_for_email(email: Vec<String>) -> Result<Vec<gpgme::Key>, Box<dyn Error>> {
    let mut gpg_ctx = Context::from_protocol(Protocol::OpenPgp)?;
    let mode = KeyListMode::empty();
    gpg_ctx.set_key_list_mode(mode)?;
    let gpg_keys = gpg_ctx.find_keys(email)?;
    let keys: Result<Vec::<gpgme::Key>,_> = gpg_keys.collect();
    let keys = keys?;
    Ok(keys)
}

// Converts SystemTime to a human-readable string
fn system_time_to_string(time: SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let datetime = DateTime::<Utc>::from(UNIX_EPOCH + duration);
    datetime.to_rfc3339()
}

fn print_key_info(key: &gpgme::Key) -> Result<(), Box<dyn Error>> {
    let key_id = key.id().unwrap_or("?");
    let fingerprint = key.fingerprint().unwrap_or("?");
    let expiration_date = key.subkeys().next()
        .and_then(|subkey| subkey.expiration_time())
        .map(system_time_to_string)
        .unwrap_or_else(|| "No expiration".to_string());

    println!("keyid   : {} [expires: {}]", key_id, expiration_date);
    println!("fpr     : {}", fingerprint);
    println!(
        "caps    : {}{}{}{}",
        if key.can_encrypt() { "e" } else { "" },
        if key.can_sign() { "s" } else { "" },
        if key.can_certify() { "c" } else { "" },
        if key.can_authenticate() { "a" } else { "" }
    );
    println!(
        "flags   :{}{}{}{}{}{}",
        if key.has_secret() { " secret" } else { "" },
        if key.is_revoked() { " revoked" } else { "" },
        if key.is_expired() { " expired" } else { "" },
        if key.is_disabled() { " disabled" } else { "" },
        if key.is_invalid() { " invalid" } else { "" },
        if key.is_qualified() { " qualified" } else { "" }
    );
    let gpg_user_ids = key.user_ids();
    for (i, user) in gpg_user_ids.enumerate() {
        println!("userid {i}: {}", user.id().unwrap_or("[none]"));
        println!("valid  {i}: {:?}", user.validity())
    }
    println!();
    Ok(())
}

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
        // let keys = get_gpg_keys_for_email(email);
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
