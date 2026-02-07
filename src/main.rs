use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::env;
use std::process::{Command, Stdio};

fn main() {
    println!("GhostShell v0.1.0 - A Modern Rust Shell for Windows and Linux");
    println!("Type 'help' for available commands, 'exit' to quit.\n");

    let mut rl = DefaultEditor::new().expect("Failed to create editor");

    loop {
        let prompt = get_prompt();
        let readline = rl.readline(&prompt);

        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                rl.add_history_entry(line).ok();

                if !execute_command(line) {
                    break;
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("exit");
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }
}

fn get_prompt() -> String {
    let cwd = env::current_dir()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "?".to_string());
    format!("ghostshell:{}> ", cwd)
}

fn execute_command(input: &str) -> bool {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return true;
    }

    let command = parts[0];
    let args = &parts[1..];

    match command {
        "exit" | "quit" => return false,
        "cd" => handle_cd(args),
        "help" => handle_help(),
        "pwd" => handle_pwd(),
        "echo" => handle_echo(args),
        "clear" | "cls" => handle_clear(),
        "env" => handle_env(),
        "export" => handle_export(args),
        _ => handle_external_command(command, args),
    }

    true
}

fn handle_cd(args: &[&str]) {
    let new_dir = if args.is_empty() {
        // Get home directory in a cross-platform way
        if cfg!(target_os = "windows") {
            match env::var("USERPROFILE") {
                Ok(home) => home,
                Err(_) => {
                    eprintln!("cd: USERPROFILE not set");
                    return;
                }
            }
        } else {
            match env::var("HOME") {
                Ok(home) => home,
                Err(_) => {
                    eprintln!("cd: HOME not set");
                    return;
                }
            }
        }
    } else {
        args[0].to_string()
    };

    if let Err(e) = env::set_current_dir(&new_dir) {
        eprintln!("cd: {}: {}", new_dir, e);
    }
}

fn handle_help() {
    println!("GhostShell - Built-in Commands:");
    println!("  cd [dir]       - Change directory (defaults to HOME)");
    println!("  pwd            - Print working directory");
    println!("  echo [args]    - Print arguments to stdout");
    println!("  clear/cls      - Clear the screen");
    println!("  env            - Display environment variables");
    println!("  export VAR=val - Set environment variable");
    println!("  help           - Show this help message");
    println!("  exit/quit      - Exit the shell");
    println!("\nAny other command will be executed as an external program.");
}

fn handle_pwd() {
    match env::current_dir() {
        Ok(path) => println!("{}", path.display()),
        Err(e) => eprintln!("pwd: {}", e),
    }
}

fn handle_echo(args: &[&str]) {
    println!("{}", args.join(" "));
}

fn handle_clear() {
    if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/c", "cls"]).status().ok();
    } else {
        Command::new("clear").status().ok();
    }
}

fn handle_env() {
    for (key, value) in env::vars() {
        println!("{}={}", key, value);
    }
}

fn handle_export(args: &[&str]) {
    if args.is_empty() {
        eprintln!("export: usage: export VAR=value");
        return;
    }

    for arg in args {
        if let Some(pos) = arg.find('=') {
            let (key, value) = arg.split_at(pos);
            let value = &value[1..]; // Skip the '=' character
            env::set_var(key, value);
        } else {
            eprintln!("export: invalid format: {}", arg);
        }
    }
}

fn handle_external_command(command: &str, args: &[&str]) {
    let child = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", command])
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
    } else {
        Command::new(command)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
    };

    match child {
        Ok(mut child) => match child.wait() {
            Ok(status) => {
                if !status.success() {
                    if let Some(code) = status.code() {
                        eprintln!("Process exited with code: {}", code);
                    }
                }
            }
            Err(e) => eprintln!("Failed to wait for command: {}", e),
        },
        Err(e) => eprintln!("{}: command not found: {}", command, e),
    }
}
