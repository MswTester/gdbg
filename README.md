# gdbg.js - Game Debugging Toolkit for Frida

A powerful, lightweight memory debugging and analysis toolkit for game hacking and reverse engineering using Frida.

## Features

- **Memory scanning and manipulation**
  - Search for values in memory
  - Monitoring and locking memory values
  - Incremental scanning (decreased/increased values)
  - Memory tracing

- **Java method and native function inspection**
  - List and search for loaded Java classes
  - Enumerate methods of classes
  - List modules and exports
  - Hook Java methods and native functions

- **Rich command interface**
  - Command history and aliases
  - Color-coded output
  - Pagination for large results
  - Intuitive shorthand commands

- **History management**
  - Save, load, and compare scan results
  - Track memory changes over time

## Installation

1. Make sure you have Frida installed:
   ```
   pip install frida-tools
   ```

2. Download the `gdbg.js` script to your computer

3. Inject the script into your target process using Frida:
   ```
   frida -U -l gdbg.js -f com.example.app --no-pause
   ```

   Or with Frida's Python bindings:
   ```python
   import frida
   
   device = frida.get_usb_device()
   pid = device.spawn(["com.example.app"])
   session = device.attach(pid)
   script = session.create_script(open("gdbg.js").read())
   script.load()
   device.resume(pid)
   ```

## Quick Start

After loading the script, you can:

1. List all Java classes in the application:
   ```javascript
   list.class()
   ```

2. Search for a specific class:
   ```javascript
   list.class("MainActivity")
   ```

3. View methods of a class (using the index from previous result):
   ```javascript
   list.method(0)
   ```

4. Hook a method (using the index from previous result):
   ```javascript
   hook.method(3)
   ```

5. Scan for an integer value in memory:
   ```javascript
   scan.type(100)
   ```

6. Filter scan results to find values that have increased:
   ```javascript
   scan.increased()
   ```

7. Lock a memory address to a specific value:
   ```javascript
   mem.lock(0, 999)
   ```

8. Get help on a specific command:
   ```javascript
   help("scan.type")
   ```

## Command Reference

### Navigation and Display

- `help([command])` - Display help information
- `nxt([offset], [count])` - Navigate through logs
- `prev([count])` - Go to previous page of logs
- `sort()` - Sort current logs

### Class and Method Inspection

- `list.class([pattern])` - List Java classes
- `list.method(class, [pattern])` - List methods of a class
- `list.module([pattern])` - List loaded modules
- `list.export(module, [pattern])` - List exports of a module
- `find(pattern)` - Alias for list.class(pattern)
- `methods(class)` - Alias for list.method(class)

### Hooking

- `hook.method(index)` - Hook Java method
- `hook.native(index)` - Hook native function
- `hookm(index)` - Alias for hook.method(index)
- `hookn(index)` - Alias for hook.native(index)

### Memory Operations

- `scan.type(value, [type], [prot])` - Scan memory
- `scan.next(condFn, [type])` - Filter results by condition
- `scan.value(value, [type])` - Find exact values
- `scan.range(min, max, [type])` - Find values in range
- `scan.increased([type])` - Find increased values
- `scan.decreased([type])` - Find decreased values
- `mem.read(index, [type])` - Read memory
- `mem.write(index, value, [type])` - Write memory
- `mem.lock(index, value, [type])` - Lock memory value
- `mem.unlock(index)` - Unlock memory
- `mem.locked()` - Show locked memory
- `mem.trace(index, [type])` - Trace memory access
- `mem.watch(index, callback, [type])` - Watch for changes

### History Management

- `hist.save([label])` - Save current logs
- `hist.list()` - List saved histories
- `hist.load(index)` - Load history
- `hist.clear()` - Clear history
- `hist.compare(index1, index2)` - Compare histories

### Configuration and Utilities

- `config.show()` - Show current settings
- `config.set(key, value)` - Change settings
- `cmd.history()` - Show command history
- `cmd.alias(name, command)` - Create command alias
- `sav(index)` - Save log item to library
- `ls()` - List saved library items

## Memory Types

The following memory types are supported:

- `byte` - Unsigned 8-bit integer
- `short` - Unsigned 16-bit integer
- `int` - Signed 32-bit integer
- `uint` - Unsigned 32-bit integer
- `float` - 32-bit floating point
- `string` - UTF-8 string
- `bytes` - Byte array

## Examples

### Finding and Hooking a Method

```javascript
// Search for the player class
list.class("Player")

// List methods in the first result
list.method(0)

// Hook the setHealth method (assuming it's at index 5)
hook.method(5)
```

### Memory Scanning and Manipulation

```javascript
// Scan for player health (value 100)
scan.type(100)

// Take note of the current values
hist.save("Full Health")

// Filter for values that decreased after taking damage
scan.decreased()

// Lock the first result to 999
mem.lock(0, 999)

// Check locked memory addresses
mem.locked()

// Unlock the first locked memory
mem.unlock(0)
```

### Creating Custom Aliases

```javascript
// Create an alias to search for health values
cmd.alias("findHealth", "scan.type(100, 'int')")

// Use the new alias
findHealth()

// Create an alias with parameters
cmd.alias("lockHealth", "mem.lock($0, 999)")

// Use the parameterized alias
lockHealth(0)
```

## License

This project is released under the MIT License.

## Acknowledgements

This tool was built using Frida (https://frida.re), a dynamic instrumentation toolkit. 