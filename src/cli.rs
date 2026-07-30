use crate::error::WatchkeyError;

pub enum Command {
    Get { service: String },
    Set { service: String },
    Delete { service: String },
    List,
    Reset,
    CompanionEnroll { base_url: String, code: String },
    CompanionEnable,
    CompanionDisable,
    CompanionUnpair,
    Version,
    Help,
}

pub fn parse() -> Result<Command, WatchkeyError> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let Some(command) = args.first() else {
        print_help();
        return Err(WatchkeyError::InvalidArgument(String::new()));
    };

    match command.as_str() {
        "get" => {
            let service = args.get(1).cloned().unwrap_or_default();
            Ok(Command::Get { service })
        }
        "set" => {
            let flags: Vec<&String> = args[1..].iter().filter(|a| a.starts_with("--")).collect();
            let positional: Vec<&String> =
                args[1..].iter().filter(|a| !a.starts_with("--")).collect();
            let service = positional
                .first()
                .map(|s| s.to_string())
                .unwrap_or_default();

            if flags.iter().any(|f| f.as_str() == "--import") {
                return Err(WatchkeyError::NotSupportedOnWindows("--import".to_string()));
            }

            let gui = flags.iter().any(|f| f.as_str() == "--gui");
            if gui {
                return Err(WatchkeyError::NotSupportedOnWindows("--gui".to_string()));
            }

            Ok(Command::Set { service })
        }
        "delete" => {
            let service = args.get(1).cloned().unwrap_or_default();
            Ok(Command::Delete { service })
        }
        "list" => Ok(Command::List),
        "reset" => Ok(Command::Reset),
        "companion" => match args.get(1).map(String::as_str) {
            Some("enroll") if args.len() == 4 => Ok(Command::CompanionEnroll {
                base_url: args[2].clone(),
                code: args[3].clone(),
            }),
            Some("enable") if args.len() == 2 => Ok(Command::CompanionEnable),
            Some("disable") if args.len() == 2 => Ok(Command::CompanionDisable),
            Some("unpair") if args.len() == 2 => Ok(Command::CompanionUnpair),
            _ => Err(WatchkeyError::InvalidArgument(
                "Usage: watchkey companion <enroll <https-url> <code>|enable|disable|unpair>"
                    .into(),
            )),
        },
        "version" | "--version" | "-v" => Ok(Command::Version),
        "help" | "--help" | "-h" => Ok(Command::Help),
        other => {
            eprintln!("Unknown command: {other}");
            print_help();
            Err(WatchkeyError::InvalidArgument(String::new()))
        }
    }
}

pub fn print_help() {
    eprint!(
        "\
watchkey — Access secrets with Windows Hello

Usage:
  watchkey get <service>              Retrieve a secret
  watchkey set <service>              Store a secret (reads from stdin)
  watchkey delete <service>           Delete a stored secret
  watchkey list                       List all stored keys
  watchkey reset                      Remove all stored data and start fresh
  watchkey companion enroll <url> <code>
                                      Store a disabled Companion pairing
  watchkey companion enable           Enable remote approval prompts
  watchkey companion disable          Return to local-only authentication
  watchkey companion unpair           Remove the local Companion pairing

Examples:
  watchkey set DOPPLER_TOKEN_DEV
  $env:DOPPLER_TOKEN = $(watchkey get DOPPLER_TOKEN_DEV)

"
    );
}
