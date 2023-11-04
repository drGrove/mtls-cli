use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server to run command against
    #[arg(short, long)]
    server: String,
    /// Config file
    #[arg(short, long)]
    config: std::path::PathBuf,
}

fn main() {
    let args = Args::parse();
}
