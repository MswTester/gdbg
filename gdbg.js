'use strict';

// Configuration and state management
const CONFIG = {
    version: "0.3.1",
    pageSize: 20,        // Number of items to display per page
    scanInterval: 200,   // Memory scan interval (ms)
    defaultScanType: 'int',
    colors: {
        enabled: true,   // Enable colored logging
        info: '\x1b[36m',    // Cyan
        success: '\x1b[32m',  // Green
        error: '\x1b[31m',    // Red
        warning: '\x1b[33m',  // Yellow
        reset: '\x1b[0m'      // Reset color
    }
};

// Global state
global.state = {
    logs: [],
    lib: [],
    hist: [],
    locks: [],
    hooks: [],
    logIndex: 0,
    lastScanType: CONFIG.defaultScanType,
    commands: []  // Command history
};

// Utility functions
const utils = {
    getTime() {
        return new Date().toTimeString().split(' ')[0];
    },

    autoLabel() {
        const t = state.logs[0]?.type || 'logs';
        return `[${t}] ${state.logs.length} items @ ${this.getTime()}`;
    },

    resolve(i, expectedType) {
        if (typeof i !== 'number') return i;
        const l = state.lib[i];
        if (l?.type === expectedType) return l.value;
        const g = state.logs[i];
        if (g?.type === expectedType) return g.value;
        return null;
    },

    formatAddress(addr) {
        if (!addr) return 'null';
        return addr.toString();
    },

    truncate(str, maxLength = 80) {
        if (!str) return '';
        if (str.length <= maxLength) return str;
        return str.substring(0, maxLength - 3) + '...';
    },
    
    toPattern(t, v) {
        const length = (
            t === "int" ||
            t === "uint" ||
            t === "float"
        ) ? 4 : (
            t === "long" ||
            t === "ulong" ||
            t === "double"
        ) ? 8 : 1
        if (t === 'string' || t === 'bytes') return v;
        const b = new ArrayBuffer(length), dv = new DataView(b);
        if (t === 'int') dv.setInt32(0, v, true);
        if (t === 'uint') dv.setUint32(0, v, true);
        if (t === 'float') dv.setFloat32(0, v, true);
        return Array.from(new Uint8Array(b)).map(b => ('0' + b.toString(16)).slice(-2)).join(' ');
    }
};

// Logging system
const log = {
    format(type, msg) {
        const c = CONFIG.colors;
        if (!c.enabled) return msg;
        
        switch (type) {
            case 'info': return `${c.info}${msg}${c.reset}`;
            case 'success': return `${c.success}${msg}${c.reset}`;
            case 'error': return `${c.error}${msg}${c.reset}`;
            case 'warning': return `${c.warning}${msg}${c.reset}`;
            default: return msg;
        }
    },

    info(msg) {
        console.log(this.format('info', `[i] ${msg}`));
    },

    success(msg) {
        console.log(this.format('success', `[+] ${msg}`));
    },

    error(msg) {
        console.log(this.format('error', `[!] ${msg}`));
    },

    warning(msg) {
        console.log(this.format('warning', `[*] ${msg}`));
    },

    table(items, formatter) {
        if (!items || !items.length) {
            this.info('No data to display');
            return;
        }

        // Simplified output for all environments
        items.forEach((item, idx) => console.log(formatter(item, idx)));
    }
};

// Memory read/write utilities
const memory = {
    reader: {
        byte: a => a.readU8(),
        short: a => a.readU16(),
        int: a => a.readS32(),
        uint: a => a.readU32(),
        float: a => a.readFloat(),
        string: a => a.readUtf8String(),
        bytes: (a, l = 8) => a.readByteArray(l)
    },

    writer: {
        byte: (a, v) => a.writeU8(v),
        short: (a, v) => a.writeU16(v),
        int: (a, v) => a.writeS32(v),
        uint: (a, v) => a.writeU32(v),
        float: (a, v) => a.writeFloat(v)
    }
};

// Core functionality
global.help = function(cmd) {
    if (!cmd) {
        log.info('Available commands:');
        console.log('  help([command])         - Display help information');
        console.log('  clss([pattern])         - List Java classes');
        console.log('  meths(class, [pattern]) - List methods of a class');
        console.log('  modls([pattern])        - List loaded modules');
        console.log('  exps(module, [pattern]) - List exports of a module');
        console.log('  hookm(index)            - Hook Java method');
        console.log('  hookn(index)            - Hook native function');
        console.log('  unhook(index)           - Unhook a method or function');
        console.log('  hooked()                - List hooked methods/functions');
        console.log('  calln(index, ...args)   - Call a native function');
        console.log('  callj(index, [methodIdx], ...args) - Call a Java method');
        console.log('  grep(pattern, [opts])   - Filter results by regex');
        console.log('  srch(value, [type], [prot]) - Scan memory');
        console.log('  exct(condFn, [type])    - Filter results by condition');
        console.log('  v(index, [lines], [type]) - View memory in hex+type format');
        console.log('  sav(index, [offset])    - Save pointer or offset to library');
        console.log('  nxt([offset], [count])  - Navigate next logs');
        console.log('  prv([offset])           - Navigate previous logs');
        console.log('  sort()                  - Sort current logs');
        console.log('  ls([index], [count])    - Display library values');
        return;
    }

    // Command-specific help
    switch(cmd) {
        case 'list.class':
            log.info('list.class([pattern]) - List Java classes');
            console.log('  pattern: Optional, substring to search in class names');
            break;
        case 'list.method':
            log.info('list.method(class, [pattern]) - List methods of a class');
            console.log('  class: Class index or name');
            console.log('  pattern: Optional, substring to search in method names');
            break;
        case 'scan.type':
            log.info('scan.type(value, [type], [prot]) - Scan memory');
            console.log('  value: Value to search for');
            console.log('  type: byte, short, int, uint, float, string (default: int)');
            console.log('  prot: Memory protection, e.g. r--, rw- (default: r--)');
            break;
        case 'mem.lock':
            log.info('mem.lock(index, value, [type]) - Lock memory value');
            console.log('  index: Pointer index');
            console.log('  value: Value to lock to');
            console.log('  type: Memory type (default: pointer\'s type)');
            break;
        case 'mem.view':
            log.info('mem.view(index, [lines], [type]) - View memory in hex and type format');
            console.log('  index: Pointer index');
            console.log('  lines: Number of 16-byte lines to display (default: 4)');
            console.log('         Use negative number to show memory before the pointer');
            console.log('  type: Memory representation: byte, short, int, uint, float (default: byte)');
            console.log('Note: Each line shows 16 bytes in both hex and type-specific format');
            break;
        case 'sav':
            log.info('sav(index, [offset]) - Save the value from logs or memory view to library');
            console.log('  index: Logs index or pointer for memory view');
            console.log('  offset: Optional, byte offset within memory view (0-15 per line)');
            console.log('          For example, sav(0, 12) saves byte at position C in first line');
            break;
        case 'grep':
            log.info('grep(pattern, [options]) - Filter results by regex');
            console.log('  pattern: Regular expression pattern to search for');
            console.log('  options: Object with optional settings:');
            console.log('    {caseSensitive: true/false, field: "label"/"type"/"value"}');
            break; 
        case 'hook.unhook':
            log.info('hook.unhook(index) - Unhook a method or function');
            console.log('  index: Hook index from hook.list()');
            break;
        case 'call.native':
            log.info('call.native(index, ...args) - Call a native function');
            console.log('  index: Function index from logs or library');
            console.log('  args: Arguments to pass to the function');
            break;
        case 'call.java':
            log.info('call.java(index, [methodIdx], ...args) - Call a Java method');
            console.log('  index: Method index from logs or library');
            console.log('  methodIdx: Optional, overload index (default: 0)');
            console.log('  args: Arguments to pass to the method');
            console.log('Note: Static methods are called directly. For non-static methods,');
            console.log('      the tool attempts to create a new instance of the class.');
            break;
        default:
            log.warning(`No help available for '${cmd}'. Use help() to see all commands.`);
    }
};

global.nxt = function (o = CONFIG.pageSize, s = CONFIG.pageSize) {
    state.logIndex += o;
    if (state.logIndex < 0) state.logIndex = 0;
    if (state.logIndex >= state.logs.length) state.logIndex = Math.max(0, state.logs.length - s);
    
    log.info(`Items ${state.logIndex + 1}-${Math.min(state.logIndex + s, state.logs.length)} / ${state.logs.length}`);
    
    const items = state.logs.slice(state.logIndex, Math.min(state.logIndex + s, state.logs.length));
    
    if (!items.length) {
        log.info('No items to display');
        return;
    }
    
    items.forEach(l => console.log(`[${l.index}] ${l.label}`));
};

global.prv = function(s = CONFIG.pageSize) {
    nxt(-s, s);
};

global.sav = function (i, offset) {
    // If offset is provided, it means we're saving from a memory view with offset
    if (offset !== undefined) {
        try {
            const v = utils.resolve(i, 'ptr');
            if (!v) return log.error(`sav(): Invalid pointer @ ${i}`);
            
            const baseAddr = v.address || v;
            
            // Calculate actual offsets
            const lineOffset = Math.floor(offset / 16) * 16;
            const byteOffset = offset % 16;
            const targetAddr = baseAddr.add(lineOffset + byteOffset);
            
            // Create a new log entry for the specific address
            const ptr = {
                index: state.lib.length,
                label: `${utils.formatAddress(targetAddr)} (ptr from view offset ${offset})`,
                value: { address: targetAddr, type: 'byte' },
                type: 'ptr'
            };
            
            state.lib.push(ptr);
            log.success(`Saved address with offset ${offset} as lib[${state.lib.length - 1}]`);
            return;
        } catch (e) {
            log.error(`sav(): ${e}`);
            return;
        }
    }
    
    // Original behavior for saving a log entry
    const l = state.logs[i];
    if (!l) return log.error(`sav(): Invalid logs index ${i}`);
    state.lib.push({ ...l });
    log.success(`Saved as lib[${state.lib.length - 1}]`);
};

global.sort = function () {
    if (!state.logs.length) return log.error("sort(): No logs");
    const t = state.logs[0].type;
    let sorted = [...state.logs];

    try {
        if (t === 'class' || t === 'func' || t === 'method') {
            sorted.sort((a, b) => a.label.localeCompare(b.label));
        } else if (t === 'module') {
            sorted.sort((a, b) => a.value.base.toString().localeCompare(b.value.base.toString()));
        } else if (t === 'ptr') {
            sorted.sort((a, b) => a.value.address.toString().localeCompare(b.value.address.toString()));
        } else {
            return log.error(`sort(): Unsupported type "${t}"`);
        }

        state.logs.length = 0;
        sorted.forEach((x, i) => {
            x.index = i;
            state.logs.push(x);
        });

        log.success(`Sorted by ${t}`);
        nxt(0);
    } catch (e) {
        log.error(`sort() failed: ${e}`);
    }
};

global.grep = function(pattern, options = {}) {
    if (!state.logs.length) return log.error('grep: No logs to search');
    
    const caseSensitive = options.caseSensitive !== undefined ? options.caseSensitive : false;
    const matchField = options.field || 'label';
    
    try {
        log.info(`grep: Searching for "${pattern}" ${caseSensitive ? 'case sensitive' : 'case insensitive'}...`);
        
        // 정규식 객체 생성
        const regex = new RegExp(pattern, caseSensitive ? '' : 'i');
        
        // 검색 결과 저장
        const searchResults = [];
        
        state.logs.forEach(item => {
            const testValue = matchField === 'label' ? item.label : 
                             (matchField === 'type' ? item.type : 
                             (matchField === 'value' ? JSON.stringify(item.value) : item.label));
            
            if (regex.test(testValue)) {
                searchResults.push({...item});
            }
        });
        
        if (searchResults.length === 0) {
            log.info(`grep: No matches found for pattern "${pattern}"`);
            return;
        }
        
        // 기존 로그 백업
        hist.save('Before grep search');
        
        // 검색 결과로 로그 업데이트
        state.logs.length = 0;
        searchResults.forEach((item, idx) => {
            state.logs.push({
                ...item,
                index: idx
            });
        });
        
        log.success(`grep: Found ${searchResults.length} matches`);
        nxt(0);
    } catch (e) {
        if (e instanceof SyntaxError) {
            log.error(`grep: Regular expression error - ${e.message}`);
        } else {
            log.error(`grep: ${e.message}`);
        }
    }
};

global.config = {
    show() {
        log.info('Current settings:');
        console.log(`  Page size: ${CONFIG.pageSize}`);
        console.log(`  Colored output: ${CONFIG.colors.enabled ? 'enabled' : 'disabled'}`);
        console.log(`  Default scan type: ${CONFIG.defaultScanType}`);
    },
    
    set(key, value) {
        if (key === 'pageSize') {
            if (typeof value !== 'number' || value < 1) {
                return log.error('pageSize must be a positive number');
            }
            CONFIG.pageSize = value;
            log.success(`Page size set to ${value}`);
        } else if (key === 'colors') {
            CONFIG.colors.enabled = !!value;
            log.success(`Colored output ${value ? 'enabled' : 'disabled'}`);
        } else if (key === 'defaultScanType') {
            if (!['byte', 'short', 'int', 'uint', 'float', 'string'].includes(value)) {
                return log.error('Invalid scan type');
            }
            CONFIG.defaultScanType = value;
            log.success(`Default scan type set to ${value}`);
        } else {
            log.error(`Unknown setting: ${key}`);
        }
    }
};

global.list = {
    class(k = '') {
        Java.perform(() => {
            try {
                log.info(`Searching classes: "${k || 'all'}"`);
                const r = Java.enumerateLoadedClassesSync()
                    .filter(c => c.toLowerCase().includes(k.toLowerCase()));
                
                state.logs.length = 0;
                r.forEach((c, i) =>
                    state.logs.push({ index: i, label: c, value: c, type: 'class' })
                );
                
                log.success(`Found ${r.length} classes`);
                nxt(0);
            } catch (e) {
                log.error(`list.class(): ${e}`);
            }
        });
    },

    method(cls, k = '') {
        const c = utils.resolve(cls, 'class');
        if (!c) return log.error(`list.method(): Invalid class @ ${cls}`);
        
        Java.perform(() => {
            try {
                log.info(`Searching methods in ${c}: "${k || 'all'}"`);
                const clz = Java.use(c);
                const m = Object.getOwnPropertyNames(clz.__proto__)
                    .filter(x => clz[x]?.overloads)
                    .filter(x => !k || x.toLowerCase().includes(k.toLowerCase()));
                
                state.logs.length = 0;
                m.forEach((m, i) =>
                    state.logs.push({
                        index: i,
                        label: `[${c.split('.').pop()}] ${m}`,
                        value: { class: c, method: m },
                        type: 'method'
                    })
                );
                
                log.success(`Found ${m.length} methods`);
                nxt(0);
            } catch (e) {
                log.error(`list.method(): ${e}`);
            }
        });
    },

    module(k = '') {
        try {
            log.info(`Searching modules: "${k || 'all'}"`);
            const mods = Process.enumerateModules()
                .filter(m => m.name.toLowerCase().includes(k.toLowerCase()));
            
            state.logs.length = 0;
            mods.forEach((m, i) =>
                state.logs.push({
                    index: i,
                    label: `${utils.formatAddress(m.base)} | ${m.name} (${m.size}B)`,
                    value: { name: m.name, base: m.base, size: m.size },
                    type: 'module'
                })
            );
            
            log.success(`Found ${mods.length} modules`);
            nxt(0);
        } catch (e) {
            log.error(`list.module(): ${e}`);
        }
    },

    export(lib, k = '') {
        const m = utils.resolve(lib, 'module');
        if (!m) return log.error(`list.export(): Invalid module @ ${lib}`);
        
        try {
            log.info(`Searching exports in ${m.name}: "${k || 'all'}"`);
            const e = Module.enumerateExportsSync(m.name)
                .filter(x => x.name.toLowerCase().includes(k.toLowerCase()));
            
            state.logs.length = 0;
            e.forEach((f, i) =>
                state.logs.push({
                    index: i,
                    label: `${utils.formatAddress(f.address)} | ${f.name} (${f.type})`,
                    value: { ...f, lib: m.name, base: m.base },
                    type: 'func'
                })
            );
            
            log.success(`Found ${e.length} exports`);
            nxt(0);
        } catch (e) {
            log.error(`list.export(): ${e}`);
        }
    }
};

global.hook = {
    method(i) {
        const { class: c, method: m } = state.logs[i]?.value || {};
        if (!c || !m) return log.error(`hook.method(): Invalid method @ ${i}`);
        
        Java.perform(() => {
            try {
                log.info(`Hooking ${c}.${m}...`);
                const clz = Java.use(c);
                const overloads = [];
                
                clz[m].overloads.forEach((o, idx) => {
                    overloads.push({
                        index: idx,
                        args: o.argumentTypes.map(t => t.className).join(', ')
                    });
                    
                    o.implementation = function (...a) {
                        log.success(`${c}.${m}(${a.join(', ')})`);
                        const r = o.call(this, ...a);
                        console.log(`  → Return: ${r}`);
                        return r;
                    };
                });
                
                // Store hooked method info
                state.hooks.push({
                    type: 'java',
                    class: c,
                    method: m,
                    overloads: overloads,
                    time: utils.getTime()
                });
                
                log.success(`Hooked ${c}.${m}`);
            } catch (e) {
                log.error(`hook.method(): ${e}`);
            }
        });
    },

    native(i) {
        const v = utils.resolve(i, 'func');
        if (!v?.address) return log.error(`hook.native(): Invalid func @ ${i}`);
        
        try {
            log.info(`Hooking ${v.name} function...`);
            Interceptor.attach(v.address, {
                onEnter(args) {
                    log.success(`${v.name} called`);
                    let i = 0;
                    while (i <= 5) {
                        try {
                            console.log(`  arg${i}: ${utils.formatAddress(args[i])} | ${args[i].toUInt32()}`);
                            i++;
                        } catch (e) {
                            break;
                        }
                    }
                },
                onLeave(r) {
                    console.log(`  → Return: ${utils.formatAddress(r)}`);
                }
            });
            
            // Store hooked native function info
            state.hooks.push({
                type: 'native',
                name: v.name,
                address: v.address,
                lib: v.lib,
                time: utils.getTime()
            });
            
            log.success(`Hooked ${v.name}`);
        } catch (e) {
            log.error(`hook.native(): ${e}`);
        }
    },
    
    list() {
        if (!state.hooks.length) return log.info("No active hooks");
        
        log.info(`${state.hooks.length} active hooks:`);
        state.hooks.forEach((h, i) => {
            if (h.type === 'java') {
                console.log(`[${i}] [Java] ${h.class}.${h.method} (${h.overloads.length} overloads) @ ${h.time}`);
            } else if (h.type === 'native') {
                console.log(`[${i}] [Native] ${h.name} @ ${utils.formatAddress(h.address)} (${h.lib}) @ ${h.time}`);
            }
        });
    },
    
    unhook(i) {
        const h = state.hooks[i];
        if (!h) return log.error(`hook.unhook(): Invalid hook index @ ${i}`);
        
        try {
            if (h.type === 'java') {
                Java.perform(() => {
                    try {
                        const clz = Java.use(h.class);
                        // Restore original implementation
                        clz[h.method].overloads.forEach(o => {
                            o.implementation = null;
                        });
                        log.success(`Unhooked Java method: ${h.class}.${h.method}`);
                        state.hooks.splice(i, 1);
                    } catch (e) {
                        log.error(`Failed to unhook Java method: ${e}`);
                    }
                });
            } else if (h.type === 'native') {
                Interceptor.detachAll(h.address);
                log.success(`Unhooked native function: ${h.name} @ ${utils.formatAddress(h.address)}`);
                state.hooks.splice(i, 1);
            }
        } catch (e) {
            log.error(`hook.unhook(): ${e}`);
        }
    },
    
    unhookAll() {
        if (!state.hooks.length) return log.info("No hooks to remove");
        
        try {
            // Unhook Java methods
            Java.perform(() => {
                state.hooks.filter(h => h.type === 'java').forEach(h => {
                    try {
                        const clz = Java.use(h.class);
                        clz[h.method].overloads.forEach(o => {
                            o.implementation = null;
                        });
                    } catch (e) {
                        log.error(`Failed to unhook ${h.class}.${h.method}: ${e}`);
                    }
                });
            });
            
            // Unhook native functions
            state.hooks.filter(h => h.type === 'native').forEach(h => {
                Interceptor.detachAll(h.address);
            });
            
            const count = state.hooks.length;
            state.hooks.length = 0;
            log.success(`Unhooked ${count} hooks`);
        } catch (e) {
            log.error(`hook.unhookAll(): ${e}`);
        }
    }
};

global.call = {
    native(i, ...args) {
        const v = utils.resolve(i, 'func');
        if (!v?.address) return log.error(`call.native(): Invalid func @ ${i}`);
        
        try {
            log.info(`Calling ${v.name} @ ${utils.formatAddress(v.address)}...`);
            
            // Prepare arguments
            const parsedArgs = args.map(arg => {
                if (typeof arg === 'number') {
                    return ptr(arg.toString());
                }
                return arg;
            });
            
            // Call the function
            const result = new NativeFunction(v.address, 'pointer', Array(parsedArgs.length).fill('pointer'))(
                ...parsedArgs
            );
            
            log.success(`Called ${v.name}`);
            console.log(`  → Return: ${utils.formatAddress(result)} | ${result.toUInt32()}`);
            return result;
        } catch (e) {
            log.error(`call.native(): ${e}`);
            return null;
        }
    },
    
    method(i, methodIdx = 0, ...args) {
        const m = utils.resolve(i, 'method');
        if (!m?.class || !m?.method) return log.error(`call.java(): Invalid method @ ${i}`);
        
        Java.perform(() => {
            try {
                log.info(`Calling ${m.class}.${m.method}...`);
                const clz = Java.use(m.class);
                
                // Check if method exists
                if (!clz[m.method] || !clz[m.method].overloads) {
                    return log.error(`call.java(): Method ${m.method} not found in class ${m.class}`);
                }
                
                // Get all available overloads
                const overloads = clz[m.method].overloads;
                
                if (methodIdx >= overloads.length) {
                    log.error(`call.java(): Invalid overload index ${methodIdx}, max is ${overloads.length - 1}`);
                    // List available overloads
                    overloads.forEach((o, idx) => {
                        const argTypes = o.argumentTypes.map(t => t.className).join(', ');
                        console.log(`  [${idx}] ${m.method}(${argTypes})`);
                    });
                    return;
                }
                
                const selectedMethod = overloads[methodIdx];
                const argTypes = selectedMethod.argumentTypes.map(t => t.className).join(', ');
                
                log.info(`Using overload: ${m.method}(${argTypes})`);
                
                let result;
                // Check if method is static or instance based on return type
                const isStatic = selectedMethod.type.className.includes("static");
                
                if (isStatic) {
                    // For static methods
                    result = selectedMethod.call(clz, ...args);
                } else {
                    // For instance methods, we need an instance
                    try {
                        // Try to get a new instance
                        const instance = clz.$new();
                        result = selectedMethod.call(instance, ...args);
                    } catch (e) {
                        log.error(`Could not create instance of ${m.class}: ${e}`);
                        log.info(`For non-static methods, you may need to obtain an instance separately`);
                        return;
                    }
                }
                
                log.success(`Called ${m.class}.${m.method}`);
                console.log(`  → Return: ${result}`);
                return result;
            } catch (e) {
                log.error(`call.java(): ${e}`);
                return null;
            }
        });
    }
};

global.scan = {
    type(val, t = CONFIG.defaultScanType, p = 'r--') {
        state.logs.length = 0;
        state.lastScanType = t;
        let idx = 0, count = 0;
        
        try {
            log.info(`Scanning memory (type: ${t}, value: ${val}, prot: ${p})...`);
            Process.enumerateRanges({ protection: p }).forEach(r => {
                Memory.scanSync(r.base, r.size, utils.toPattern(t, val)).forEach(res => {
                    state.logs.push({
                        index: idx++,
                        label: `${utils.formatAddress(res.address)} (${t})`,
                        value: { address: res.address, type: t },
                        type: 'ptr'
                    });
                    count++;
                });
            });
            log.success(`Scan complete: found ${count} results`);
            nxt(0);
        } catch (e) {
            log.error(`scan.type(): ${e}`);
        }
    },

    next(cond, t = state.lastScanType) {
        if (!state.logs.length) return log.error('scan.next(): No previous scan results');
        
        const snapshot = state.logs.map(x => x.value.address);
        state.logs.length = 0;
        let idx = 0, count = 0;
        
        log.info(`Filtering ${snapshot.length} addresses with condition...`);
        
        snapshot.forEach(ptr => {
            try {
                const val = memory.reader[t](ptr);
                if (cond(val)) {
                    state.logs.push({
                        index: idx++,
                        label: `${utils.formatAddress(ptr)} (${t}) = ${val}`,
                        value: { address: ptr, type: t },
                        type: 'ptr'
                    });
                    count++;
                }
            } catch (_) {}
        });
        
        state.lastScanType = t;
        log.success(`Filter complete: found ${count} results`);
        nxt(0);
    },
    
    value(val, t = state.lastScanType) {
        this.next(v => v === val, t);
    },
    
    range(min, max, t = state.lastScanType) {
        this.next(v => v >= min && v <= max, t);
    },
    
    increased(t = state.lastScanType) {
        if (!state.logs.some(l => l.hasOwnProperty('prevValue'))) {
            // First snapshot
            const snapshot = state.logs.map(l => ({
                address: l.value.address,
                value: memory.reader[t](l.value.address)
            }));
            
            state.logs.forEach((l, i) => {
                try {
                    l.prevValue = memory.reader[t](l.value.address);
                } catch (_) {}
            });
            
            log.info('Snapshot saved for increased value search. Run scan.increased() again to find values that increased.');
            return;
        }
        
        this.next(function(v) {
            const idx = state.logs.findIndex(l => 
                l.value.address.equals(this.address) && l.hasOwnProperty('prevValue'));
            return idx >= 0 && v > state.logs[idx].prevValue;
        }, t);
    },
    
    decreased(t = state.lastScanType) {
        if (!state.logs.some(l => l.hasOwnProperty('prevValue'))) {
            state.logs.forEach((l, i) => {
                try {
                    l.prevValue = memory.reader[t](l.value.address);
                } catch (_) {}
            });
            
            log.info('Snapshot saved for decreased value search. Run scan.decreased() again to find values that decreased.');
            return;
        }
        
        this.next(function(v) {
            const idx = state.logs.findIndex(l => 
                l.value.address.equals(this.address) && l.hasOwnProperty('prevValue'));
            return idx >= 0 && v < state.logs[idx].prevValue;
        }, t);
    }
};

global.mem = {
    read(i, t = "int") {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.read(): Invalid pointer @ ${i}`);
        const addr = v.address || v, type = t || v.type;
        
        try {
            const val = memory.reader[type](addr);
            log.info(`[${utils.formatAddress(addr)}] = ${val}`);
            return val;
        } catch (e) {
            log.error(`mem.read(): ${e}`);
        }
    },

    write(i, val, t) {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.write(): Invalid pointer @ ${i}`);
        const addr = v.address || v, type = t || v.type;
        
        try {
            const oldVal = memory.reader[type](addr);
            memory.writer[type](addr, val);
            log.success(`Changed: ${oldVal} → ${val} @ ${utils.formatAddress(addr)}`);
        } catch (e) {
            log.error(`mem.write(): ${e}`);
        }
    },

    view(i, lines = 10, t = "byte") {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.view(): Invalid pointer @ ${i}`);
        const baseAddr = v.address || v;
        const absLines = Math.abs(lines);
        
        try {
            // Determine line offset based on lines parameter
            const startOffset = lines < 0 ? -16 * absLines : 0;
            const totalLines = lines < 0 ? absLines * 2 : absLines;
            
            // Print header
            console.log('                       0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F');
            
            for (let lineIdx = 0; lineIdx < totalLines; lineIdx++) {
                const lineOffset = startOffset + (lineIdx * 16);
                const currentAddr = baseAddr.add(lineOffset);
                let hexValues = '';
                let typeValues = '';
                
                try {
                    // Get bytes for the current line
                    const bytes = currentAddr.readByteArray(16);
                    const bytesArray = Array.from(new Uint8Array(bytes));
                    
                    // Format bytes as hex
                    hexValues = bytesArray.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
                    
                    // Format type-specific values
                    if (t === 'byte') {
                        // Just use hex values
                        typeValues = '';
                    } else if (t === 'int' || t === 'uint') {
                        // Show 4 32-bit integers per line (every 4 bytes)
                        typeValues = '  ';
                        for (let j = 0; j < 16; j += 4) {
                            if (j + 3 < 16) {
                                try {
                                    const intValue = t === 'int' 
                                        ? currentAddr.add(j).readS32() 
                                        : currentAddr.add(j).readU32();
                                    typeValues += intValue.toString().padStart(10, ' ') + '  ';
                                } catch (e) {
                                    typeValues += '          ';
                                }
                            }
                        }
                    } else if (t === 'short') {
                        // Show 8 16-bit values per line (every 2 bytes)
                        typeValues = '  ';
                        for (let j = 0; j < 16; j += 2) {
                            if (j + 1 < 16) {
                                try {
                                    const shortValue = currentAddr.add(j).readS16();
                                    typeValues += shortValue.toString().padStart(6, ' ') + '  ';
                                } catch (e) {
                                    typeValues += '      ';
                                }
                            }
                        }
                    } else if (t === 'float') {
                        // Show 4 floats per line (every 4 bytes)
                        typeValues = '  ';
                        for (let j = 0; j < 16; j += 4) {
                            if (j + 3 < 16) {
                                try {
                                    const floatValue = currentAddr.add(j).readFloat().toFixed(2);
                                    typeValues += floatValue.padStart(8, ' ') + '  ';
                                } catch (e) {
                                    typeValues += '        ';
                                }
                            }
                        }
                    }
                } catch (e) {
                    hexValues = 'Cannot read memory';
                }
                
                // Print the line
                console.log(`[${lineIdx}] ${utils.formatAddress(currentAddr)}  ${hexValues}${typeValues}`);
            }
            
            log.info(`Memory view of ${totalLines} lines at ${utils.formatAddress(baseAddr.add(startOffset))}, type: ${t}`);
            return baseAddr;
        } catch (e) {
            log.error(`mem.view(): ${e}`);
        }
    },

    lock(i, val, t) {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.lock(): Invalid pointer @ ${i}`);
        const addr = v.address || v, type = t || v.type;
        
        try {
            const id = setInterval(() => {
                try {
                    if (memory.reader[type](addr) !== val)
                        memory.writer[type](addr, val);
                } catch (_) {}
            }, CONFIG.scanInterval);
            
            state.locks.push({ id, addr, type, val });
            log.success(`Locked [${utils.formatAddress(addr)}] = ${val}`);
        } catch (e) {
            log.error(`mem.lock(): ${e}`);
        }
    },

    unlock(i) {
        const l = state.locks[i];
        if (!l) return log.error(`mem.unlock(): No lock at index ${i}`);
        
        clearInterval(l.id);
        state.locks.splice(i, 1);
        log.success(`Unlocked [${utils.formatAddress(l.addr)}]`);
    },

    locked() {
        if (!state.locks.length) return log.info("No locked memory");
        
        log.table(state.locks, (l, i) => 
            `[${i}] ${utils.formatAddress(l.addr)} (${l.type}) = ${l.val}`
        );
    },

    trace(i, t) {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.trace(): Invalid pointer @ ${i}`);
        const addr = v.address || v, type = t || v.type;
        
        try {
            Interceptor.attach(addr, {
                onAccess({ address, accessType, stackData }) {
                    try {
                        const val = memory.reader[type](address);
                        log.info(`[Trace] ${utils.formatAddress(address)}: ${val} (${accessType})`);
                    } catch (_) {}
                }
            });
            log.success(`Tracing [${utils.formatAddress(addr)}]`);
        } catch (e) {
            log.error(`mem.trace(): ${e}`);
        }
    },
    
    watch(i, callback, t) {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.watch(): Invalid pointer @ ${i}`);
        if (typeof callback !== 'function') return log.error('mem.watch(): Callback function required');
        
        const addr = v.address || v, type = t || v.type;
        let lastVal;
        
        try {
            lastVal = memory.reader[type](addr);
            const id = setInterval(() => {
                try {
                    const newVal = memory.reader[type](addr);
                    if (newVal !== lastVal) {
                        callback(newVal, lastVal, addr);
                        lastVal = newVal;
                    }
                } catch (_) {}
            }, CONFIG.scanInterval);
            
            state.locks.push({ 
                id, addr, type, isWatcher: true,
                desc: 'Value change monitoring' 
            });
            
            log.success(`Watching for changes at [${utils.formatAddress(addr)}]`);
        } catch (e) {
            log.error(`mem.watch(): ${e}`);
        }
    }
};

global.hist = {
    save(label = '') {
        const finalLabel = label || utils.autoLabel();
        state.hist.push({
            index: state.hist.length,
            label: finalLabel,
            time: utils.getTime(),
            count: state.logs.length,
            data: state.logs.map(x => ({ ...x }))
        });
        log.success(`hist[${state.hist.length - 1}] "${finalLabel}" saved (${state.logs.length} items)`);
    },

    list() {
        if (!state.hist.length) return log.info("No history saved");
        
        log.table(state.hist, h => 
            `[${h.index}] ${h.label} | ${h.count} items | ${h.time}``[${h.index}] ${h.label} | ${h.count} items | ${h.time}`
        );
    },

    load(i) {
        const h = state.hist[i];
        if (!h) return log.error(`hist.load(): No history at index ${i}`);
        
        state.logs.length = 0;
        state.logs.push(...h.data.map((x, j) => ({ ...x, index: j })));
        log.success(`hist[${i}] "${h.label}" loaded (${h.count} items)`);
        nxt(0);
    },

    clear() {
        state.hist.length = 0;
        log.success(`History cleared`);
    },
    
    compare(i, j) {
        const h1 = state.hist[i];
        const h2 = state.hist[j];
        
        if (!h1 || !h2) return log.error('hist.compare(): Invalid history indices');
        
        const h1Map = new Map(h1.data.map(d => [d.value?.address?.toString() || d.label, d]));
        const h2Map = new Map(h2.data.map(d => [d.value?.address?.toString() || d.label, d]));
        
        const added = [...h2Map.keys()].filter(k => !h1Map.has(k));
        const removed = [...h1Map.keys()].filter(k => !h2Map.has(k));
        
        log.info(`Comparing ${h1.label} <-> ${h2.label}:`);
        log.success(`Added items: ${added.length}`);
        log.warning(`Removed items: ${removed.length}`);
        
        if (added.length > 0) {
            console.log('--- Added items ---');
            added.forEach(k => console.log(h2Map.get(k).label));
        }
        
        if (removed.length > 0) {
            console.log('--- Removed items ---');
            removed.forEach(k => console.log(h1Map.get(k).label));
        }
    }
};

// Command control features
global.cmd = {
    history() {
        if (!state.commands.length) return log.info("No command history");
        state.commands.forEach((c, i) => console.log(`${i}: ${c}`));
    },
    
    alias(name, command) {
        if (!name || !command) return log.error("Usage: cmd.alias(name, command)");
        
        global[name] = function(...args) {
            // Insert arguments into command string
            const cmd = command.replace(/\$(\d+)/g, (_, i) => {
                const arg = args[parseInt(i, 10)];
                if (arg === undefined) return _;
                return typeof arg === 'string' ? `"${arg}"` : arg;
            });
            
            try {
                return eval(cmd);
            } catch (e) {
                log.error(`Alias execution failed: ${e}`);
            }
        };
        
        log.success(`Added alias '${name}' -> '${command}'`);
    }
};

// Setup command proxy for pre/post processing
(function setupCommandProxy() {
    const originalEval = global.eval;
    global.eval = function(cmd) {
        if (typeof cmd === 'string' && cmd.trim() && 
            !cmd.startsWith('(') && !cmd.startsWith('function')) {
            state.commands.push(cmd);
            if (state.commands.length > 100) state.commands.shift();
        }
        return originalEval.call(this, cmd);
    };
})();

// Detect environment
(function detectEnvironment() {
    try {
        if (ObjC.available) {
            log.info('iOS environment detected');
        } else if (Java.available) {
            log.info('Android environment detected');
        }
    } catch (_) {
        // No specific environment detected
    }
})();

// Enhanced library management
global.lib = {
    // Save current log item to library
    save: global.sav,
    
    // List library items with pagination
    list(page = 0, size = CONFIG.pageSize) {
        if(!state.lib.length) return log.error("ls(): No values in lib");
        
        const start = page * size;
        const end = Math.min(start + size, state.lib.length);
        
        if (start >= state.lib.length) {
            return log.error(`ls(): Page ${page} exceeds available items (total: ${state.lib.length})`);
        }
        
        log.info(`Library items ${start}-${end-1} / ${state.lib.length}`);
        const items = state.lib.slice(start, end);
        
        log.table(items, (item, idx) => 
            `[${start + idx}] ${item.label} (${item.type})`
        );
        
        if (end < state.lib.length) {
            log.info(`Use ls(${page + 1}) to see the next page`);
        }
    },
    
    // Clear all library items
    clear() {
        if (!state.lib.length) return log.info("Library is already empty");
        const count = state.lib.length;
        state.lib.length = 0;
        log.success(`Cleared ${count} items from library`);
    },
    
    // Remove an item by index
    remove(idx) {
        if (idx < 0 || idx >= state.lib.length) {
            return log.error(`lib.remove(): Invalid index ${idx}`);
        }
        
        const removed = state.lib.splice(idx, 1)[0];
        log.success(`Removed lib[${idx}]: ${removed.label}`);
        
        // Reindex remaining items
        state.lib.forEach((item, i) => {
            if (item.index !== undefined) item.index = i;
        });
    },
    
    // Move an item from one index to another
    move(fromIdx, toIdx) {
        if (fromIdx < 0 || fromIdx >= state.lib.length) {
            return log.error(`lib.move(): Invalid source index ${fromIdx}`);
        }
        
        if (toIdx < 0 || toIdx >= state.lib.length) {
            return log.error(`lib.move(): Invalid target index ${toIdx}`);
        }
        
        if (fromIdx === toIdx) {
            return log.info(`Item is already at index ${fromIdx}`);
        }
        
        // Get item to move
        const item = state.lib[fromIdx];
        
        // Remove the item
        state.lib.splice(fromIdx, 1);
        
        // Insert at new position
        state.lib.splice(toIdx, 0, item);
        
        // Reindex all items
        state.lib.forEach((item, i) => {
            if (item.index !== undefined) item.index = i;
        });
        
        log.success(`Moved item from lib[${fromIdx}] to lib[${toIdx}]`);
    },
    
    // Sort library items by specific field
    sort(field = 'label') {
        if (!state.lib.length) return log.error("lib.sort(): Library is empty");
        
        try {
            const sorted = [...state.lib];
            
            if (field === 'label' || field === 'type') {
                sorted.sort((a, b) => a[field].localeCompare(b[field]));
            } else if (field === 'index') {
                sorted.sort((a, b) => (a.index || 0) - (b.index || 0));
            } else if (field === 'address' && sorted[0]?.value?.address) {
                sorted.sort((a, b) => a.value.address.toString().localeCompare(b.value.address.toString()));
            } else {
                return log.error(`lib.sort(): Unsupported field "${field}"`);
            }
            
            state.lib = sorted;
            
            // Reindex all items
            state.lib.forEach((item, i) => {
                if (item.index !== undefined) item.index = i;
            });
            
            log.success(`Sorted library by ${field}`);
            ls();
        } catch (e) {
            log.error(`lib.sort() failed: ${e}`);
        }
    },
    
    // Find items in library matching a pattern
    find(pattern, field = 'label') {
        if (!state.lib.length) return log.error("lib.find(): Library is empty");
        
        if (typeof pattern === 'string') {
            pattern = pattern.toLowerCase();
        }
        
        const results = state.lib.filter(item => {
            if (field === 'label' || field === 'type') {
                return item[field].toLowerCase().includes(pattern);
            } else if (field === 'index') {
                return item.index === pattern;
            } else if (field === 'address' && item.value?.address) {
                return item.value.address.toString().includes(pattern);
            }
            return false;
        });
        
        if (!results.length) {
            return log.info(`No matches found for "${pattern}" in ${field}`);
        }
        
        log.success(`Found ${results.length} matches:`);
        log.table(results, (item, idx) => 
            `[${state.lib.indexOf(item)}] ${item.label} (${item.type})`
        );
        
        return results;
    },
    
    // Export item from library to log
    export(idx) {
        if (idx < 0 || idx >= state.lib.length) {
            return log.error(`lib.export(): Invalid index ${idx}`);
        }
        
        const item = state.lib[idx];
        state.logs.push({ ...item, index: state.logs.length });
        log.success(`Exported lib[${idx}] to logs[${state.logs.length - 1}]`);
        return state.logs.length - 1;
    },
    
    // Create a copy of an item
    duplicate(idx) {
        if (idx < 0 || idx >= state.lib.length) {
            return log.error(`lib.duplicate(): Invalid index ${idx}`);
        }
        
        const item = state.lib[idx];
        state.lib.push({ ...item });
        log.success(`Duplicated lib[${idx}] to lib[${state.lib.length - 1}]`);
        return state.lib.length - 1;
    }
};

// Alias for shorthand usage
global.clss = global.list.class.bind(global.list);
global.meths = global.list.method.bind(global.list);
global.modls = global.list.module.bind(global.list);
global.exps = global.list.export.bind(global.list);
global.hookm = global.hook.method.bind(global.hook);
global.hookn = global.hook.native.bind(global.hook);
global.unhook = global.hook.unhook.bind(global.hook);
global.hooked = global.hook.list.bind(global.hook);
global.calln = global.call.native.bind(global.call);
global.callm = global.call.method.bind(global.call);
global.srch = global.scan.type.bind(global.scan);
global.exct = global.scan.value.bind(global.scan);
global.ls = global.lib.list.bind(global.lib);
global.mv = global.lib.move.bind(global.lib);
global.rm = global.lib.remove.bind(global.lib);
global.r = global.mem.read.bind(global.mem);
global.w = global.mem.write.bind(global.mem);
global.l = global.mem.lock.bind(global.mem);
global.ul = global.mem.unlock.bind(global.mem);
global.v = global.mem.view.bind(global.mem);

// Initial info message
console.log(`
        _____ _____  ____   _____ 
       / ____|  __ \\|  _ \\ / ____|
      | |  __| |  | | |_) | |  __ 
      | | |_ | |  | |  _ <| | |_ |
      | |__| | |__| | |_) | |__| |
       \\_____|_____/|____/ \\_____|
`);
console.log(`
===========================================
    Game Debugger & Memory Tool v${CONFIG.version}
          Created by @MswTester
===========================================
`);

log.info('gdbg.js loaded. Type help() to see available commands.');

