# GhostShell

A modern, cross-platform shell written in Rust for Windows and Linux (2026).

## Features

- **Cross-Platform**: Works seamlessly on both Windows and Linux
- **Built-in Commands**: Common shell commands like `cd`, `pwd`, `echo`, `env`, and more
- **External Command Execution**: Run any system command
- **Command History**: Navigate through previous commands with arrow keys
- **Environment Variables**: View and set environment variables
- **Modern Implementation**: Written in Rust for safety and performance

## Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo (comes with Rust)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/AcerThyRacer/GhostShell.git
cd GhostShell

# Build the project
cargo build --release

# The binary will be available at target/release/ghostshell
```

### Running

```bash
# Run directly with cargo
cargo run

# Or run the compiled binary
./target/release/ghostshell  # Linux/macOS
target\release\ghostshell.exe  # Windows
```

## Usage

### Built-in Commands

- `cd [dir]` - Change directory (defaults to HOME if no directory specified)
- `pwd` - Print working directory
- `echo [args]` - Print arguments to stdout
- `clear` / `cls` - Clear the screen
- `env` - Display all environment variables
- `export VAR=value` - Set an environment variable
- `help` - Show help message with all built-in commands
- `exit` / `quit` - Exit the shell

### External Commands

Any command not recognized as a built-in will be executed as an external program:

```bash
# On Linux/Unix
ls -la
grep "pattern" file.txt
git status

# On Windows
dir
type file.txt
ipconfig
```

### Command History

Use the **Up** and **Down** arrow keys to navigate through your command history.

## Examples

```bash
# Basic navigation
ghostshell:~> cd /tmp
ghostshell:/tmp> pwd
/tmp

# Environment variables
ghostshell:~> export MY_VAR=hello
ghostshell:~> env | grep MY_VAR
MY_VAR=hello

# External commands
ghostshell:~> echo "Hello from GhostShell!"
Hello from GhostShell!

ghostshell:~> ls -l
# Lists files in current directory
```

## Architecture

GhostShell is built with:
- **rustyline**: For readline-like command input with history support
- **std::process**: For spawning external commands
- **Cross-platform support**: Platform-specific handling for Windows and Unix-like systems

## Development

### Running Tests

```bash
cargo test
```

### Linting

```bash
cargo clippy
```

### Formatting

```bash
cargo fmt
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Roadmap

Future enhancements may include:
- [ ] Command piping and redirection
- [ ] Job control (background processes)
- [ ] Tab completion
- [ ] Shell scripting support
- [ ] Configuration file support
- [ ] Custom themes and prompts
- [ ] Aliases