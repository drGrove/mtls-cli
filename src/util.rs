use std::error::Error;
use std::io::Write;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use gpgme;
use which::which;

pub const CONFIG_DIR_PREFIX: &str = "mtls";

pub fn inquire(prompt: String) -> String {
    print!("{} ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    return input.trim().to_string();
}

pub fn get_gpg_ctx() -> gpgme::Context {
    let mut gpg_ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)
        .expect("Could not instantiate GPG context");
    // Using which to ensure that we get the users current gpg path.
    // This allows things like the qubes split-gpg proxy to work
    let gpg_path = which("gpg").unwrap().display().to_string();
    let _ = gpg_ctx.set_engine_path(gpg_path);
    return gpg_ctx
}

pub fn get_gpg_keys_for_email(email: Vec<String>) -> Result<Vec<gpgme::Key>, Box<dyn Error>> {
    let mut gpg_ctx = get_gpg_ctx();
    let mode = gpgme::KeyListMode::empty();
    gpg_ctx.set_key_list_mode(mode)?;
    let gpg_keys = gpg_ctx.find_keys(email)?;
    let keys: Result<Vec::<gpgme::Key>,_> = gpg_keys.collect();
    let keys = keys?;
    Ok(keys)
}

// Converts SystemTime to a human-readable string
pub fn system_time_to_string(time: SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let datetime = DateTime::<Utc>::from(UNIX_EPOCH + duration);
    datetime.to_rfc3339()
}

pub fn print_key_info(key: &gpgme::Key) -> Result<(), Box<dyn Error>> {
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

pub fn sign_data() {

}
