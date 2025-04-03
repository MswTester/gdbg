'use strict';

// Configuration and state management
const CONFIG = {
    pageSize: 10,        // Number of items to display per page
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
        if (t === 'string' || t === 'bytes') return v;
        const b = new ArrayBuffer(4), dv = new DataView(b);
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
        items.forEach(item => console.log(formatter(item)));
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
        console.log('  list.class([pattern])   - List Java classes');
        console.log('  list.method(class, [pattern]) - List methods of a class');
        console.log('  list.module([pattern])  - List loaded modules');
        console.log('  list.export(module, [pattern]) - List exports of a module');
        console.log('  hook.method(index)      - Hook Java method');
        console.log('  hook.native(index)      - Hook native function');
        console.log('  scan.type(value, [type], [prot]) - Scan memory');
        console.log('  scan.next(condFn, [type]) - Filter results by condition');
        console.log('  mem.read/write/lock/unlock/trace - Memory operations');
        console.log('  nxt([offset], [count])  - Navigate through logs');
        console.log('  sort()                  - Sort current logs');
        console.log('  hist.save/list/load/clear - History management');
        console.log('  config                  - View/change settings');
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
        default:
            log.warning(`No help available for '${cmd}'. Use help() to see all commands.`);
    }
};

global.nxt = function (o = 0, s = CONFIG.pageSize) {
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

global.prev = function(s = CONFIG.pageSize) {
    nxt(-s, s);
};

global.sav = function (i) {
    const l = state.logs[i];
    if (!l) return log.error(`sav(): Invalid logs index ${i}`);
    state.lib.push({ ...l });
    log.success(`Saved as lib[${state.lib.length - 1}]`);
};

global.ls = function () {
    if(!state.lib.length) return log.error("ls(): No values in lib");
    log.table(state.lib, item => `[${item.index}] ${item.label} (${item.type})`);
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
                    label: `${utils.formatAddress(m.base)} | ${m.name}`,
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
                clz[m].overloads.forEach(o => {
                    o.implementation = function (...a) {
                        log.success(`${c}.${m}(${a.join(', ')})`);
                        const r = o.call(this, ...a);
                        console.log(`  → Return: ${r}`);
                        return r;
                    };
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
                    for (let i = 0; i < 5; i++) 
                        console.log(`  arg${i}: ${utils.formatAddress(args[i])}`);
                },
                onLeave(r) {
                    console.log(`  → Return: ${utils.formatAddress(r)}`);
                }
            });
            log.success(`Hooked ${v.name}`);
        } catch (e) {
            log.error(`hook.native(): ${e}`);
        }
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
    read(i, t) {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.read(): Invalid pointer @ ${i}`);
        const addr = v.address, type = t || v.type;
        
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
        const addr = v.address, type = t || v.type;
        
        try {
            const oldVal = memory.reader[type](addr);
            memory.writer[type](addr, val);
            log.success(`Changed: ${oldVal} → ${val} @ ${utils.formatAddress(addr)}`);
        } catch (e) {
            log.error(`mem.write(): ${e}`);
        }
    },

    lock(i, val, t) {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.lock(): Invalid pointer @ ${i}`);
        const addr = v.address, type = t || v.type;
        
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
        const addr = v.address, type = t || v.type;
        
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
        
        const addr = v.address, type = t || v.type;
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
            `[${h.index}] ${h.label} | ${h.count} items | ${h.time}`
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
            const cmd = command.replace(/\$(\d+)/g, (_, i) => 
                args[parseInt(i, 10)] !== undefined ? args[parseInt(i, 10)] : _);
            
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
        if (typeof ObjC !== 'undefined') {
            log.info('iOS environment detected');
        } else if (typeof Java !== 'undefined') {
            log.info('Android environment detected');
        }
    } catch (_) {
        // No specific environment detected
    }
})();

// Pre-defined useful aliases
cmd.alias('find', 'list.class($0)');
cmd.alias('methods', 'list.method($0)');
cmd.alias('mods', 'list.module($0)');
cmd.alias('exports', 'list.export($0, $1)');
cmd.alias('search', 'scan.type($0, $1)');
cmd.alias('exact', 'scan.value($0, $1)');
cmd.alias('hookm', 'hook.method($0)');
cmd.alias('hookn', 'hook.native($0)');
cmd.alias('r', 'mem.read($0, $1)');
cmd.alias('w', 'mem.write($0, $1, $2)');
cmd.alias('l', 'mem.lock($0, $1, $2)');
cmd.alias('ul', 'mem.unlock($0)');

// Initial info message
log.info('gdbg.js loaded. Type help() to see available commands.');