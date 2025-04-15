/**
 * REPL command evaluator
 */

const repl = require('repl');

/**
 * Create command evaluator
 * @param {any} script Frida script
 * @returns {Function} Command evaluation function
 */
function createEvaluator(script) {
  return async function(cmd, context, filename, callback) {
    cmd = cmd.trim();
    
    if (!cmd) {
      return callback(null);
    }
    
    // Parse command (with quotes support)
    const parts = parseCommand(cmd);
    const command = parts[0];
    const args = parts.slice(1);
    
    try {
      await executeCommand(script, command, args);
      callback(null);
    } catch (e) {
      callback(new repl.Recoverable(e));
    }
  };
}

/**
 * Parse command string into argument array (supports spaces inside quotes)
 * @param {string} cmdStr Command string
 * @returns {string[]} Parsed argument array
 */
function parseCommand(cmdStr) {
  const result = [];
  let current = '';
  let inQuotes = false;
  let quoteChar = '';
  
  for (let i = 0; i < cmdStr.length; i++) {
    const char = cmdStr[i];
    
    // Handle quotes
    if ((char === '"' || char === "'") && (i === 0 || cmdStr[i-1] !== '\\')) {
      if (!inQuotes) {
        inQuotes = true;
        quoteChar = char;
      } else if (char === quoteChar) {
        inQuotes = false;
      } else {
        current += char;
      }
      continue;
    }
    
    // Handle spaces
    if (char === ' ' && !inQuotes) {
      if (current) {
        result.push(current);
        current = '';
      }
      continue;
    }
    
    current += char;
  }
  
  if (current) {
    result.push(current);
  }
  
  return result;
}

/**
 * Check if string is a hexadecimal address
 * @param {string} str String to check
 * @returns {boolean} Whether it's a hex address
 */
function isHexAddress(str) {
  return /^0x[0-9a-fA-F]+$/.test(str);
}

/**
 * Convert hexadecimal address string to ptr() call
 * @param {string} addr Hexadecimal address string
 * @returns {string} Converted JS code
 */
function convertHexAddress(addr) {
  if (isHexAddress(addr)) {
    return `ptr("${addr}")`;
  }
  return addr;
}

/**
 * Execute command
 * @param {any} script Frida script
 * @param {string} cmd Command
 * @param {string[]} args Command arguments
 */
async function executeCommand(script, cmd, args) {
  try {
    let jsCode = '';
    
    switch(cmd) {
      // Basic commands
      case 'help':
        if (args.length === 0) {
          showHelp();
          return;
        }
        jsCode = `help(${JSON.stringify(args[0])})`;
        break;
        
      // List commands
      case 'list':
        if (args.length === 0) {
          console.error('Usage: list <type> [pattern]');
          console.error('Types: class, method, module, export');
          return;
        }
        
        const listType = args[0];
        const listArgs = args.slice(1);
        
        switch(listType) {
          case 'class':
            jsCode = `list.class(${listArgs.length > 0 ? JSON.stringify(listArgs[0]) : ''})`;
            break;
          case 'method':
            if (listArgs.length === 0) {
              console.error('Usage: list method <class> [pattern]');
              return;
            }
            jsCode = `list.method(${JSON.stringify(listArgs[0])}, ${listArgs.length > 1 ? JSON.stringify(listArgs[1]) : ''})`;
            break;
          case 'module':
            jsCode = `list.module(${listArgs.length > 0 ? JSON.stringify(listArgs[0]) : ''})`;
            break;
          case 'export':
            if (listArgs.length === 0) {
              console.error('Usage: list export <module> [pattern]');
              return;
            }
            jsCode = `list.export(${JSON.stringify(listArgs[0])}, ${listArgs.length > 1 ? JSON.stringify(listArgs[1]) : ''})`;
            break;
          default:
            console.error(`Unknown list type: ${listType}`);
            return;
        }
        break;
        
      // Memory manipulation commands
      case 'mem':
        if (args.length < 2) {
          console.error('Usage: mem <action> [args...]');
          console.error('Actions: read, write, view, lock, unlock, list, watch, unwatch, trace, untrace');
          return;
        }
        
        const action = args[1];
        
        switch(action) {
          case 'read':
            if (args.length === 0) {
              console.error('Usage: mem read <address> [type]');
              return;
            }
            // Handle hex address
            const addrRead = isHexAddress(args[0]) ? convertHexAddress(args[0]) : JSON.stringify(args[0]);
            jsCode = `mem.read(${addrRead}, ${args.length > 1 ? JSON.stringify(args[1]) : ''})`;
            break;
          case 'write':
            if (args.length < 2) {
              console.error('Usage: mem write <address> <value> [type]');
              return;
            }
            // Handle hex address
            const addrWrite = isHexAddress(args[0]) ? convertHexAddress(args[0]) : JSON.stringify(args[0]);
            jsCode = `mem.write(${addrWrite}, ${JSON.stringify(args[1])}, ${args.length > 2 ? JSON.stringify(args[2]) : ''})`;
            break;
          case 'view':
            if (args.length === 0) {
              console.error('Usage: mem view <address> [type] [lines]');
              return;
            }
            // Handle hex address
            const addrView = isHexAddress(args[0]) ? convertHexAddress(args[0]) : JSON.stringify(args[0]);
            jsCode = `mem.view(${addrView}, ${args.length > 1 ? JSON.stringify(args[1]) : ''}, ${args.length > 2 ? args[2] : ''})`;
            break;
          case 'lock':
            if (args.length < 4) {
              console.error('Usage: mem lock <address> <value> [type]');
              return;
            }
            const addr = args[2];
            const value = args[3];
            const type = args[4] || 'int';
            
            jsCode = `mem.lock(${addr}, ${value}, ${type})`;
            break;
          case 'unlock':
            if (args.length < 3) {
              console.error('Usage: mem unlock <id>');
              return;
            }
            const id = parseInt(args[2]);
            
            jsCode = `mem.unlock(${id})`;
            break;
          case 'locked':
            console.info('mem locked is now mem list. Please use mem list from now on.');
            jsCode = `mem.list()`;
            break;
          case 'list':
            jsCode = `mem.list()`;
            break;
          case 'trace':
            if (args.length < 3) {
              console.error('Usage: mem trace <address> [type]');
              return;
            }
            const addrTrace = isHexAddress(args[2]) ? convertHexAddress(args[2]) : JSON.stringify(args[2]);
            jsCode = `mem.trace(${addrTrace}, ${args.length > 3 ? JSON.stringify(args[3]) : ''})`;
            break;
          case 'untrace':
            if (args.length < 3) {
              console.error('Usage: mem untrace <id>');
              return;
            }
            const idTrace = parseInt(args[2]);
            
            jsCode = `mem.untrace(${idTrace})`;
            break;
          case 'watch':
            if (args.length < 3) {
              console.error('Usage: mem watch <address> [type]');
              return;
            }
            const addrWatch = isHexAddress(args[2]) ? convertHexAddress(args[2]) : JSON.stringify(args[2]);
            jsCode = `mem.watch(${addrWatch}, ${args.length > 3 ? JSON.stringify(args[3]) : ''})`;
            break;
          case 'unwatch':
            if (args.length < 3) {
              console.error('Usage: mem unwatch <id>');
              return;
            }
            const idWatch = parseInt(args[2]);
            
            jsCode = `mem.unwatch(${idWatch})`;
            break;
          default:
            console.error(`Unknown mem action: ${action}`);
            console.error('Actions: read, write, view, list, lock, unlock, watch, unwatch, trace, untrace');
            return;
        }
        break;
        
      // Scan commands
      case 'scan':
        if (args.length === 0) {
          console.error('Usage: scan <action> [args...]');
          console.error('Actions: type, value, range, increased, decreased, next');
          return;
        }
        
        const scanAction = args[0];
        const scanArgs = args.slice(1);
        
        switch(scanAction) {
          case 'type':
            if (scanArgs.length === 0) {
              console.error('Usage: scan type <value> [type] [protection]');
              return;
            }
            
            // Handle value (number or string)
            let scanValue;
            if (!isNaN(Number(scanArgs[0]))) {
              // Handle number
              scanValue = scanArgs[0];
            } else {
              // Handle string
              scanValue = JSON.stringify(scanArgs[0]);
            }
            
            const scanType = scanArgs.length > 1 ? JSON.stringify(scanArgs[1]) : '';
            const scanProt = scanArgs.length > 2 ? JSON.stringify(scanArgs[2]) : '';
            
            jsCode = `scan.type(${scanValue}, ${scanType}, ${scanProt})`;
            break;
          case 'value':
            if (scanArgs.length === 0) {
              console.error('Usage: scan value <value> [type]');
              return;
            }
            // Handle value (number or string)
            let exactValue;
            if (!isNaN(Number(scanArgs[0]))) {
              exactValue = scanArgs[0];
            } else {
              exactValue = JSON.stringify(scanArgs[0]);
            }
            
            jsCode = `scan.value(${exactValue}, ${scanArgs.length > 1 ? JSON.stringify(scanArgs[1]) : ''})`;
            break;
          case 'range':
            if (scanArgs.length < 2) {
              console.error('Usage: scan range <min> <max> [type]');
              return;
            }
            jsCode = `scan.range(${scanArgs[0]}, ${scanArgs[1]}, ${scanArgs.length > 2 ? JSON.stringify(scanArgs[2]) : ''})`;
            break;
          case 'increased':
            jsCode = `scan.increased(${scanArgs.length > 0 ? JSON.stringify(scanArgs[0]) : ''})`;
            break;
          case 'decreased':
            jsCode = `scan.decreased(${scanArgs.length > 0 ? JSON.stringify(scanArgs[0]) : ''})`;
            break;
          case 'next':
            if (scanArgs.length === 0) {
              console.error('Usage: scan next <condition> [type]');
              return;
            }
            console.error('scan next command is not supported in CLI. Please use scan.next() function directly.');
            return;
          default:
            console.error(`Unknown scan action: ${scanAction}`);
            return;
        }
        break;
        
      // Hook commands
      case 'hook':
        if (args.length === 0) {
          console.error('Usage: hook <action> [args...]');
          console.error('Actions: method, native, list, unhook');
          return;
        }
        
        const hookAction = args[0];
        const hookArgs = args.slice(1);
        
        switch(hookAction) {
          case 'method':
            if (hookArgs.length === 0) {
              console.error('Usage: hook method <class.method>');
              return;
            }
            jsCode = `hook.method(${JSON.stringify(hookArgs[0])})`;
            break;
          case 'native':
            if (hookArgs.length === 0) {
              console.error('Usage: hook native <function>');
              return;
            }
            // Handle hex address
            const hookNativeArg = isHexAddress(hookArgs[0]) ? convertHexAddress(hookArgs[0]) : JSON.stringify(hookArgs[0]);
            jsCode = `hook.native(${hookNativeArg})`;
            break;
          case 'list':
            jsCode = `hook.list()`;
            break;
          case 'unhook':
            if (hookArgs.length === 0) {
              console.error('Usage: hook unhook <index>');
              return;
            }
            jsCode = `hook.unhook(${JSON.stringify(hookArgs[0])})`;
            break;
          default:
            console.error(`Unknown hook action: ${hookAction}`);
            return;
        }
        break;
        
      // Call commands
      case 'call':
        if (args.length === 0) {
          console.error('Usage: call <action> [args...]');
          console.error('Actions: native, method');
          return;
        }
        
        const callAction = args[0];
        const callArgs = args.slice(1);
        
        switch(callAction) {
          case 'native':
            if (callArgs.length === 0) {
              console.error('Usage: call native <function> [args...]');
              return;
            }
            // Handle hex address
            const callNativeArg = isHexAddress(callArgs[0]) ? convertHexAddress(callArgs[0]) : JSON.stringify(callArgs[0]);
            jsCode = `call.native(${callNativeArg}, ${callArgs.slice(1).map(arg => {
              // Numbers or hex addresses are not quoted
              if (!isNaN(Number(arg)) || isHexAddress(arg)) {
                return isHexAddress(arg) ? convertHexAddress(arg) : arg;
              }
              return JSON.stringify(arg);
            }).join(', ')})`;
            break;
          case 'method':
            if (callArgs.length < 2) {
              console.error('Usage: call method <class.method> <overloadIndex> [args...]');
              return;
            }
            jsCode = `call.method(${JSON.stringify(callArgs[0])}, ${callArgs[1]}, ${callArgs.slice(2).map(arg => {
              // Numbers are not quoted
              if (!isNaN(Number(arg))) {
                return arg;
              }
              return JSON.stringify(arg);
            }).join(', ')})`;
            break;
          default:
            console.error(`Unknown call action: ${callAction}`);
            return;
        }
        break;
        
      // History commands
      case 'hist':
        if (args.length === 0) {
          console.error('Usage: hist <action> [args...]');
          console.error('Actions: save, list, load, clear, compare');
          return;
        }
        
        const histAction = args[0];
        const histArgs = args.slice(1);
        
        switch(histAction) {
          case 'save':
            jsCode = `hist.save(${histArgs.length > 0 ? JSON.stringify(histArgs[0]) : ''})`;
            break;
          case 'list':
            jsCode = `hist.list()`;
            break;
          case 'load':
            if (histArgs.length === 0) {
              console.error('Usage: hist load <index>');
              return;
            }
            jsCode = `hist.load(${histArgs[0]})`;
            break;
          case 'clear':
            jsCode = `hist.clear()`;
            break;
          case 'compare':
            if (histArgs.length < 2) {
              console.error('Usage: hist compare <index1> <index2>');
              return;
            }
            jsCode = `hist.compare(${histArgs[0]}, ${histArgs[1]})`;
            break;
          default:
            console.error(`Unknown history action: ${histAction}`);
            return;
        }
        break;
        
      // Library commands
      case 'lib':
        if (args.length === 0) {
          console.error('Usage: lib <action> [args...]');
          console.error('Actions: list, save, clear, remove, move, sort, find, export, duplicate');
          return;
        }
        
        const libAction = args[0];
        const libArgs = args.slice(1);
        
        switch(libAction) {
          case 'list':
            jsCode = `lib.list(${libArgs.length > 0 ? libArgs[0] : ''})`;
            break;
          case 'save':
            if (libArgs.length === 0) {
              console.error('Usage: lib save <index> [label]');
              return;
            }
            jsCode = `lib.save(${libArgs[0]}, ${libArgs.length > 1 ? JSON.stringify(libArgs[1]) : ''})`;
            break;
          case 'clear':
            jsCode = `lib.clear()`;
            break;
          case 'remove':
            if (libArgs.length === 0) {
              console.error('Usage: lib remove <index>');
              return;
            }
            jsCode = `lib.remove(${libArgs[0]})`;
            break;
          case 'move':
            if (libArgs.length < 2) {
              console.error('Usage: lib move <fromIndex> <toIndex>');
              return;
            }
            jsCode = `lib.move(${libArgs[0]}, ${libArgs[1]})`;
            break;
          case 'sort':
            jsCode = `lib.sort(${libArgs.length > 0 ? JSON.stringify(libArgs[0]) : ''})`;
            break;
          case 'find':
            if (libArgs.length === 0) {
              console.error('Usage: lib find <pattern> [field]');
              return;
            }
            jsCode = `lib.find(${JSON.stringify(libArgs[0])}, ${libArgs.length > 1 ? JSON.stringify(libArgs[1]) : ''})`;
            break;
          case 'export':
            if (libArgs.length === 0) {
              console.error('Usage: lib export <index>');
              return;
            }
            jsCode = `lib.export(${libArgs[0]})`;
            break;
          case 'duplicate':
            if (libArgs.length === 0) {
              console.error('Usage: lib duplicate <index>');
              return;
            }
            jsCode = `lib.duplicate(${libArgs[0]})`;
            break;
          default:
            console.error(`Unknown library action: ${libAction}`);
            return;
        }
        break;
        
      // Command management commands
      case 'cmd':
        if (args.length === 0) {
          console.error('Usage: cmd <action> [args...]');
          console.error('Actions: history, alias');
          return;
        }
        
        const cmdAction = args[0];
        const cmdArgs = args.slice(1);
        
        switch(cmdAction) {
          case 'history':
            jsCode = `cmd.history()`;
            break;
          case 'alias':
            if (cmdArgs.length < 2) {
              console.error('Usage: cmd alias <name> <command>');
              return;
            }
            jsCode = `cmd.alias(${JSON.stringify(cmdArgs[0])}, ${JSON.stringify(cmdArgs.slice(1).join(' '))})`;
            break;
          default:
            console.error(`Unknown command action: ${cmdAction}`);
            return;
        }
        break;
        
      // Navigation commands
      case 'nxt':
        jsCode = `nxt(${args.length > 0 ? args[0] : ''})`;
        break;
      case 'prv':
        jsCode = `prv(${args.length > 0 ? args[0] : ''})`;
        break;
      case 'grep':
        if (args.length === 0) {
          console.error('Usage: grep <pattern>');
          return;
        }
        jsCode = `grep(${JSON.stringify(args[0])})`;
        break;
      case 'sav':
        if (args.length === 0) {
          console.error('Usage: sav <index>');
          return;
        }
        jsCode = `sav(${JSON.stringify(args[0])})`;
        break;
      case 'sort':
        jsCode = `sort(${args.length > 0 ? JSON.stringify(args[0]) : ''})`;
        break;
        
      // Unknown command
      default:
        console.error(`Unknown command: ${cmd}`);
        console.error('Type help for help.');
        return;
    }
    
    if (jsCode) {
      await script.exports.executeCommand(jsCode);
    }
  } catch (e) {
    console.error(`Command execution error: ${e.message}`);
    throw e;
  }
}

/**
 * Show help
 */
function showHelp() {
  console.log('Available commands:');
  console.log('  help                        - Show this help');
  console.log('  list class [pattern]        - Show class list');
  console.log('  list method <class> [p]     - Show method list of class');
  console.log('  list module [pattern]       - Show module list');
  console.log('  list export <mod> [p]       - Show export list of module');
  console.log('');
  console.log('  mem read <address> [type]   - Read value of memory address');
  console.log('  mem write <addr> <val> [t]  - Write value to memory address');
  console.log('  mem view <addr> [t] [lines] - View memory address');
  console.log('  mem lock <addr> <val> [t]   - Lock value of memory address');
  console.log('  mem unlock <index>          - Unlock memory address');
  console.log('  mem locked                  - Show locked memory list');
  console.log('  mem trace <addr> [type]     - Trace access to memory address');
  console.log('');
  console.log('  scan type <val> [t] [prot]  - Scan value in memory');
  console.log('  scan value <val> [type]     - Scan specific value');
  console.log('  scan range <min> <max> [t]  - Scan values in range');
  console.log('  scan increased [type]       - Scan increased values');
  console.log('  scan decreased [type]       - Scan decreased values');
  console.log('');
  console.log('  hook method <class.method>  - Hook Java method');
  console.log('  hook native <func>          - Hook native function');
  console.log('  hook list                   - Show hooked function list');
  console.log('  hook unhook <index>         - Remove hook');
  console.log('');
  console.log('  call native <func> [args]   - Call native function');
  console.log('  call method <m> <idx> [a]   - Call Java method');
  console.log('');
  console.log('  hist save [label]           - Save current log');
  console.log('  hist list                   - Show saved log list');
  console.log('  hist load <index>           - Load saved log');
  console.log('  hist clear                  - Clear all saved logs');
  console.log('  hist compare <idx1> <idx2>  - Compare two logs');
  console.log('');
  console.log('  lib list [page]             - Show library item');
  console.log('  lib save <index> [label]    - Save log item to library');
  console.log('  lib clear                   - Clear library');
  console.log('  lib remove <index>          - Remove library item');
  console.log('  lib move <from> <to>        - Move library item');
  console.log('  lib sort [field]            - Sort library item');
  console.log('  lib find <pattern> [field]  - Find library item');
  console.log('  lib export <index>          - Export library item to log');
  console.log('  lib duplicate <index>       - Duplicate library item');
  console.log('');
  console.log('  cmd history                 - Show command history');
  console.log('  cmd alias <name> <command>  - Create command alias');
  console.log('');
  console.log('  nxt [page]                  - Move to next page');
  console.log('  prv [page]                  - Move to previous page');
  console.log('  grep <pattern>              - Search pattern in current log');
  console.log('  sav <index> [label]         - Save log item to library');
  console.log('  sort [field]                - Sort current log');
  console.log('');
  console.log('  exit                        - Exit REPL session');
  console.log('');
  console.log('Note: "value" as argument should be quoted if it contains spaces. (e.g., "value 1")');
  console.log('      Hexadecimal address values starting with 0x can be entered directly. (e.g., 0x7ff8ad83b0)');
}

module.exports = {
  createEvaluator
}; 