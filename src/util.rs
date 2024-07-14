use std::fs;
use std::io::Write;
use std::io;
use std::path::Path;


pub fn inquire(prompt: String) -> String {
    print!("{} ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    return input.trim().to_string();
}

pub fn ensure_directory_exists(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        println!("Path does not exist. Creating: {}", path.display());
        fs::create_dir_all(path)?;
    }
    Ok(())
}
