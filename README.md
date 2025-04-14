# GDBG - Game Debugger & Memory Analysis Tool

GDBG is a powerful CLI tool for game debugging and memory analysis built on top of the Frida instrumentation toolkit. It provides an intuitive command-line interface for common Frida operations, making it easier to hook functions, scan memory, and manipulate game memory.

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

## Usage

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

## Command Reference

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

### Search Commands

- `search <value> [type] [prot]` - Scan memory
- `exact <value> [type]` - Filter results by exact value
- `grep <pattern>` - Filter results by regex

## License

MIT License

## 모듈화 구조

gdbg는 이제 두 가지 주요 부분으로 모듈화되었습니다:

1. CLI 모듈 (`src/cli`, `src/commands`, `src/repl`, `src/utils`)
   - CLI 명령어 및 REPL 기능을 담당

2. Frida 에이전트 모듈 (`src/frida`)
   - frida-compile을 사용하여 모듈화된 Frida 스크립트
   - 모든 메모리 조작 및 후킹 기능 포함

### 개발 방법

스크립트를 수정한 후에는 다음 명령어로 컴파일해야 합니다:

```bash
npm run compile-agent
```

이 명령어는 `frida-agent.js`와 모든 관련 모듈을 `gdbg.js`로 컴파일합니다.

### 모듈 구조

```
src/
├── cli/            # CLI 메인 모듈
│   ├── index.js
│   └── version.js
├── commands/       # CLI 명령어
│   ├── frida.js
│   ├── index.js
│   └── repl.js
├── repl/           # REPL 기능
│   ├── commands.js
│   ├── completer.js
│   ├── evaluator.js
│   └── index.js
├── utils/          # 공통 유틸리티
│   └── index.js
└── frida/          # Frida 에이전트 모듈
    ├── index.js    # 메인 진입점
    ├── config.js   # 설정
    ├── state.js    # 전역 상태
    ├── utils.js    # 유틸리티
    ├── logger.js   # 로깅
    ├── memory.js   # 메모리 유틸리티
    ├── help.js     # 도움말
    ├── list.js     # 목록 기능
    ├── hook.js     # 후킹 기능
    ├── call.js     # 함수 호출
    ├── scan.js     # 메모리 스캔
    ├── mem.js      # 메모리 조작
    ├── history.js  # 히스토리 관리
    ├── library.js  # 라이브러리 관리
    ├── cmd.js      # 명령어 관리
    └── navigation.js # 탐색 기능
``` 