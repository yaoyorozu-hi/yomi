mod archive;
mod status;

use crate::config::Env;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Exit codes per design §8: 0 ok · 1 error · 2 partial · 3 refused.
pub const EXIT_OK: i32 = 0;
pub const EXIT_PARTIAL: i32 = 2;
pub const EXIT_REFUSED: i32 = 3;

#[derive(Parser)]
#[command(name = "yomi", version, about = "Claude Code session-data plane")]
pub struct Cli {
    /// Storage root (overrides $YOMI_HOME and ~/.yomi).
    #[arg(long, global = true)]
    pub home: Option<PathBuf>,
    /// Path to config.toml.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    /// Emit machine-readable JSON.
    #[arg(long, global = true)]
    pub json: bool,
    /// Verbose logging.
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Capture session data into the archive store.
    Archive(archive::ArchiveArgs),
    /// Report archive state, secrets, and storage.
    Status(status::StatusArgs),
    /// Re-hash stored artifacts against the catalog.
    Verify(status::VerifyArgs),
    /// Inspect configuration.
    Config(ConfigArgs),
}

#[derive(clap::Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Print the resolved config path.
    Path,
    /// Print the effective configuration.
    Get,
}

/// Parse args and dispatch. Returns the process exit code.
pub fn run() -> Result<i32> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let env = Env::resolve(cli.home.as_deref(), cli.config.as_deref())?;

    match &cli.command {
        Command::Archive(args) => archive::run(&env, args, cli.json),
        Command::Status(args) => status::run_status(&env, args, cli.json),
        Command::Verify(args) => status::run_verify(&env, args, cli.json),
        Command::Config(args) => run_config(&env, args, cli.json),
    }
}

fn run_config(env: &Env, args: &ConfigArgs, json: bool) -> Result<i32> {
    match args.action {
        ConfigAction::Path => {
            println!("{}", env.config_path.display());
        }
        ConfigAction::Get => {
            if json {
                println!("{}", serde_json::to_string_pretty(&env.config)?);
            } else {
                println!("{}", toml::to_string_pretty(&env.config)?);
            }
        }
    }
    Ok(EXIT_OK)
}

fn init_tracing(verbose: bool) {
    let level = if verbose { "debug" } else { "warn" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .without_time()
        .try_init();
}
