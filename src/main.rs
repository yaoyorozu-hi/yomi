use std::process::ExitCode;

fn main() -> ExitCode {
    match yomi::cli::run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}
