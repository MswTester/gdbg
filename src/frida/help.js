/**
 * Help module
 */

const log = require('./logger');

// Main help function
function help(topic) {
    if (!topic) {
        log.info('Available commands (CLI style):');
        console.log('  help [command]            - Display this help');
        console.log('');
        console.log('  list class [pattern]      - List Java classes');
        console.log('  list method <class> [p]   - List methods of a class');
        console.log('  list module [pattern]     - List loaded modules');
        console.log('  list export <mod> [p]     - List exports of a module');
        console.log('');
        console.log('  mem read <addr> [type]    - Read memory');
        console.log('  mem write <addr> <val> [t]- Write memory');
        console.log('  mem view <addr> [t] [ln]  - View memory');
        console.log('  mem lock <addr> <val> [t] - Lock memory value');
        console.log('  mem unlock <index>        - Unlock memory');
        console.log('  mem locked                - List locked memory');
        console.log('  mem trace <addr> [type]   - Trace memory access');
        console.log('');
        console.log('  scan type <val> [t] [prot]- Scan value in memory');
        console.log('  scan value <val> [type]   - Scan exact value');
        console.log('  scan range <min> <max> [t]- Scan value in range');
        console.log('  scan increased [type]     - Scan for increased values');
        console.log('  scan decreased [type]     - Scan for decreased values');
        console.log('');
        console.log('  hook method <class.method>- Hook Java method');
        console.log('  hook native <func>        - Hook native function');
        console.log('  hook list                 - List hooked functions');
        console.log('  hook unhook <index>       - Remove hook');
        console.log('');
        console.log('  call native <func> [args] - Call native function');
        console.log('  call method <m> <idx> [a] - Call Java method');
        console.log('');
        console.log('  hist save [label]         - Save current log');
        console.log('  hist list                 - List saved logs');
        console.log('  hist load <index>         - Load saved log');
        console.log('  hist clear                - Clear all saved logs');
        console.log('  hist compare <idx1> <idx2>- Compare two logs');
        console.log('');
        console.log('  lib list [page]           - List library items');
        console.log('  lib save <index> [label]  - Save log to library');
        console.log('  lib clear                 - Clear library');
        console.log('  lib remove <index>        - Remove library item');
        console.log('  lib move <from> <to>      - Move library item');
        console.log('  lib sort [field]          - Sort library items');
        console.log('  lib find <pattern> [field]- Find in library');
        console.log('  lib export <index>        - Export library to log');
        console.log('  lib duplicate <index>     - Duplicate library item');
        console.log('');
        console.log('  cmd history               - Show command history');
        console.log('  cmd alias <n> <command>   - Create command alias');
        console.log('');
        console.log('  nxt [page]                - Next page');
        console.log('  prv [page]                - Previous page');
        console.log('  grep <pattern>            - Search in current log');
        console.log('  sav <index> [label]       - Save log to library');
        console.log('  sort [field]              - Sort current log');
        console.log('');
        console.log('  exit                      - Exit session');
        console.log('');
        console.log('Type "help <command>" for more information on specific commands.');
        return;
    }

    // Show detailed help for specific topics
    switch (topic.toLowerCase()) {
        case 'list':
            console.log('LIST COMMAND:');
            console.log('  List classes, methods, modules, and exports');
            console.log('');
            console.log('  list class [pattern]      - List Java classes matching pattern');
            console.log('  list method <class> [p]   - List methods of a class matching pattern');
            console.log('  list module [pattern]     - List loaded modules matching pattern');
            console.log('  list export <mod> [p]     - List exports of a module matching pattern');
            console.log('');
            console.log('Examples:');
            console.log('  list class java.lang.String  - List classes containing "java.lang.String"');
            console.log('  list method 0               - List methods of class at index 0');
            console.log('  list module libc            - List modules containing "libc"');
            console.log('  list export 0 malloc        - List exports containing "malloc" in module at index 0');
            break;

        case 'mem':
            console.log('MEMORY COMMANDS:');
            console.log('  Read, write, view and manipulate memory');
            console.log('');
            console.log('  mem read <addr> [type]     - Read memory at address with type');
            console.log('  mem write <addr> <val> [t] - Write value to memory at address');
            console.log('  mem view <addr> [t] [ln]   - View memory at address (type, lines)');
            console.log('  mem lock <addr> <val> [t]  - Lock memory to specific value');
            console.log('  mem unlock <index>         - Unlock memory at index');
            console.log('  mem list                   - List all locked memory addresses');
            console.log('  mem trace <addr> [type]    - Trace memory access and changes');
            console.log('  mem watch <addr> [type]    - Watch for memory changes');
            console.log('  mem unwatch <index>        - Stop watching memory at index');
            console.log('');
            console.log('Supported types:');
            console.log('  byte, short, int, uint, float, double, pointer, string');
            console.log('');
            console.log('Examples:');
            console.log('  mem read 0x1000 int        - Read int at address 0x1000');
            console.log('  mem write 0x1000 42 int    - Write 42 as int to address 0x1000');
            console.log('  mem view 0x1000 float 10   - View 10 lines of memory as floats');
            console.log('  mem lock 0x1000 100 int    - Lock int at 0x1000 to value 100');
            break;

        case 'scan':
            console.log('SCAN COMMANDS:');
            console.log('  Search for values in memory');
            console.log('');
            console.log('  scan type <val> [t] [prot] - Scan for value with type and protection');
            console.log('  scan value <val> [type]    - Search for exact value');
            console.log('  scan range <min> <max> [t] - Search for value in range');
            console.log('  scan increased [type]      - Search for increased values');
            console.log('  scan decreased [type]      - Search for decreased values');
            console.log('  scan unchanged [type]      - Search for unchanged values');
            console.log('  scan changed [type]        - Search for any changed values');
            console.log('');
            console.log('Supported types:');
            console.log('  byte, short, int, uint, float, double, string');
            console.log('');
            console.log('Memory protection (prot):');
            console.log('  r-x (readable, executable) - Default for code');
            console.log('  rw- (readable, writable)   - Default for data');
            console.log('  r-- (read-only)            - For constants');
            console.log('');
            console.log('Examples:');
            console.log('  scan type 100 int rw-      - Find int value 100 in writable memory');
            console.log('  scan value 3.14 float      - Find exact float value 3.14');
            console.log('  scan range 10 20 int       - Find int values between 10 and 20');
            break;

        case 'hook':
            console.log('HOOK COMMANDS:');
            console.log('  Intercept function calls');
            console.log('');
            console.log('  hook method <class.method> - Hook Java method');
            console.log('  hook native <func>         - Hook native function');
            console.log('  hook list                  - List all active hooks');
            console.log('  hook unhook <index>        - Remove hook at index');
            console.log('');
            console.log('Examples:');
            console.log('  hook method java.lang.String.length - Hook String.length()');
            console.log('  hook native malloc               - Hook malloc function');
            console.log('  hook native 0x1234               - Hook function at address 0x1234');
            break;

        case 'call':
            console.log('CALL COMMANDS:');
            console.log('  Call functions directly');
            console.log('');
            console.log('  call native <func> [args]  - Call native function with arguments');
            console.log('  call method <m> <idx> [a]  - Call Java method at index with arguments');
            console.log('');
            console.log('Examples:');
            console.log('  call native malloc 42      - Call malloc(42)');
            console.log('  call method 0 0 "test"     - Call first method of class at index 0 with arg "test"');
            break;

        case 'hist':
            console.log('HISTORY COMMANDS:');
            console.log('  Manage search history');
            console.log('');
            console.log('  hist save [label]          - Save current log with optional label');
            console.log('  hist list                  - List all saved logs');
            console.log('  hist load <index>          - Load saved log at index');
            console.log('  hist clear                 - Clear all saved logs');
            console.log('  hist compare <idx1> <idx2> - Compare two saved logs');
            break;

        case 'lib':
            console.log('LIBRARY COMMANDS:');
            console.log('  Manage library of saved items');
            console.log('');
            console.log('  lib list [page]            - List library items (paginated)');
            console.log('  lib save <index> [label]   - Save log at index to library');
            console.log('  lib clear                  - Clear all library items');
            console.log('  lib remove <index>         - Remove library item at index');
            console.log('  lib move <from> <to>       - Move library item to new position');
            console.log('  lib sort [field]           - Sort library by field');
            console.log('  lib find <pattern> [field] - Find items in library');
            console.log('  lib export <index>         - Export library item to current log');
            console.log('  lib duplicate <index>      - Duplicate library item');
            break;

        case 'cmd':
            console.log('COMMAND MANAGEMENT:');
            console.log('  Manage command history and aliases');
            console.log('');
            console.log('  cmd history                - Show command history');
            console.log('  cmd alias <name> <command> - Create command alias');
            break;

        case 'navigation':
            console.log('NAVIGATION COMMANDS:');
            console.log('  Navigate through search results');
            console.log('');
            console.log('  nxt [page]                 - Go to next page of results');
            console.log('  prv [page]                 - Go to previous page of results');
            console.log('  grep <pattern>             - Filter results by pattern');
            console.log('  sort [field]               - Sort results by field');
            break;

        default:
            console.log(`No help available for "${topic}"`);
            console.log('Type "help" for list of all commands');
    }
}

module.exports = help; 