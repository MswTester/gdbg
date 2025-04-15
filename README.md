# GDBG - Game Debugger & Memory Analysis Tool

GDBG is a powerful CLI tool for game debugging and memory analysis built on top of the Frida instrumentation toolkit. It provides an intuitive command-line interface for common Frida operations, making it easier to hook functions, scan memory, and manipulate game memory.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Using Pre-built Binaries](#using-pre-built-binaries)
  - [Building from Source](#building-from-source)
- [Getting Started](#getting-started)
  - [Basic Usage](#basic-usage)
  - [Command Examples](#command-examples)
- [Documentation](#documentation)
  - [Basic Commands](#basic-commands)
  - [Hook Commands](#hook-commands)
  - [Memory Commands](#memory-commands)
  - [Search Commands](#search-commands)
  - [History & Comparison](#history--comparison)
  - [Utility Commands](#utility-commands)
- [Architecture](#architecture)
  - [Modular Structure](#modular-structure)
  - [Development Guide](#development-guide)
- [License](#license)

## Features

- Java class/method exploration
- Native module/function hooking
- Memory scanning and manipulation
- Value locking
- Memory viewing in various formats
- History tracking and comparison
- And more...

## Installation

### Using Pre-built Binaries

Download the appropriate binary for your platform from the releases page:

- Windows: `gdbg-win.exe`
- macOS: `gdbg-macos`
- Linux: `gdbg-linux`

Make the file executable on macOS/Linux:

```bash
chmod +x gdbg-macos  # or gdbg-linux
```

### Building from Source

To build GDBG from source, you need Node.js and npm installed.

1. Clone the repository:
```bash
git clone https://github.com/MswTester/gdbg.git
cd gdbg
```

2. Install dependencies:
```bash
npm install
```

3. Build for all platforms:
```bash
npm run build-all
```

Or build for a specific platform:
```bash
npm run build-win    # Windows
npm run build-macos  # macOS
npm run build-linux  # Linux
```

The binaries will be generated in the `dist` directory.

## Getting Started

### Basic Usage

```bash
# Connect to USB device and attach to process by name
gdbg -U -n com.example.app

# Connect to remote frida-server and attach to process by PID
gdbg -R -p 1234

# Connect to specific device and spawn process
gdbg -D 123abc -f /path/to/executable
```

### Command Examples

Once in the GDBG REPL, you can run commands like:

```
# List Java classes containing "MainActivity"
list class MainActivity

# Hook a Java method
hook method 0

# Scan memory for a specific value
search 12345 int

# View memory at a specific address
view 0 10 int

# Lock a memory value
mem lock 0 100 int
```

Type `help` to see all available commands.

## Documentation

### Basic Commands

- `help` - Display help information
- `list class [pattern]` - List Java classes
- `list method <class> [pattern]` - List methods of a class
- `list module [pattern]` - List loaded modules
- `list export <module> [pattern]` - List exports of a module

### Hook Commands

- `hook method <index>` - Hook Java method
- `hook native <index>` - Hook native function
- `unhook <index>` - Unhook a method or function
- `hooked` - List hooked methods/functions

### Memory Commands

- `mem read <index> [type]` - Read value from memory address
- `mem write <index> <value> [type]` - Write value to memory address
- `mem view <index> [lines] [type]` - View memory in hex+type format
- `mem lock <index> <value> [type]` - Lock memory value
- `mem unlock <index>` - Unlock memory value
- `mem list` - List all locked memory addresses

### Search Commands

- `search <value> [type] [prot]` - Scan memory
- `exact <value> [type]` - Filter results by exact value
- `grep <pattern>` - Filter results by regex
- `next` - Continue search with next matches
- `prev` - Go back to previous matches

### History & Comparison

- `history save [name]` - Save current search results
- `history load <name>` - Load saved search results
- `history list` - List all saved search results
- `history diff <name1> <name2>` - Compare two saved results
- `history delete <name>` - Delete saved search results

### Utility Commands

- `call <index> [args...]` - Call a function
- `eval <code>` - Evaluate JavaScript code in process context
- `library load <path>` - Load a script library
- `clear` - Clear the console
- `exit` - Exit GDBG

## Architecture

### Modular Structure

GDBG is now modularized into two main components:

1. CLI Module (`src/cli`, `src/commands`, `src/repl`, `src/utils`)
   - Handles CLI commands and REPL functionality

2. Frida Agent Module (`src/frida`)
   - Modularized Frida scripts using frida-compile
   - Contains all memory manipulation and hooking functionality

### Development Guide

After modifying scripts, you need to compile them using:

```bash
npm run compile-agent
```

This command compiles `frida-agent.js` and all related modules into `gdbg.js`.

#### Module Structure

```
src/
├── cli/              # CLI main module
│   ├── index.js
│   └── version.js
├── commands/         # CLI commands
│   ├── frida.js
│   ├── index.js
│   └── repl.js
├── repl/             # REPL functionality
│   ├── commands.js
│   ├── completer.js
│   ├── evaluator.js
│   └── index.js
├── utils/            # Common utilities
│   └── index.js
└── frida/            # Frida agent module
    ├── index.js      # Main entry point
    ├── config.js     # Configuration
    ├── state.js      # Global state
    ├── utils.js      # Utilities
    ├── logger.js     # Logging
    ├── memory.js     # Memory utilities
    ├── help.js       # Help system
    ├── list.js       # Listing functionality
    ├── hook.js       # Hooking functionality
    ├── call.js       # Function calling
    ├── scan.js       # Memory scanning
    ├── mem.js        # Memory manipulation
    ├── history.js    # History management
    ├── library.js    # Library management
    ├── cmd.js        # Command management
    └── navigation.js # Navigation functionality
``` 

## License

MIT License 