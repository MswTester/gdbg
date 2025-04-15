/**
 * Memory manipulation module
 */

const utils = require('./utils');
const log = require('./logger');

const locks = {};
const lockIndex = [];
const traces = {};
const traceIndex = [];
const watches = {};
const watchIndex = [];

let lockCounter = 0;
let traceCounter = 0;
let watchCounter = 0;

const mem = {
    read(i, t = "uint") {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.read(): Invalid pointer @ ${i}`);
        const addr = v.address || v, type = t || v.type;
        
        try {
            const memory = require('./memory');
            const val = memory.reader[type](addr);
            log.info(`Memory read: [${utils.formatAddress(addr)}] (${type}) = ${val}`);
            return val;
        } catch (e) {
            log.error(`mem.read() error: ${e}`);
        }
    },

    write(i, val, t) {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.write(): Invalid pointer @ ${i}`);
        const addr = v.address || v, type = t || v.type;
        
        try {
            const memory = require('./memory');
            const oldVal = memory.reader[type](addr);
            memory.writer[type](addr, val);
            log.success(`Memory write completed: ${utils.formatAddress(addr)} (${type}) [${oldVal} → ${val}]`);
        } catch (e) {
            log.error(`mem.write() error: ${e}`);
        }
    },

    view(i, t = "byte", lines = 10) {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.view(): Invalid pointer @ ${i}`);
        const baseAddr = v.address || v;
        const absLines = Math.abs(lines);
        
        try {
            // Determine line offset based on lines parameter
            const startOffset = lines < 0 ? -16 * absLines : 0;
            const totalLines = lines < 0 ? absLines * 2 : absLines;
            
            log.info(`Viewing memory at address ${utils.formatAddress(baseAddr.add(startOffset))} for ${totalLines} lines (type: ${t})`);
            
            // Print header
            console.log('                      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F');
            
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
                console.log(`[${lineIdx}] ${utils.formatAddress(currentAddr).padEnd(16, ' ')}  ${hexValues}${typeValues}`);
            }
            
            return baseAddr;
        } catch (e) {
            log.error(`mem.view() error: ${e}`);
        }
    },

    /**
     * Lock a memory address to maintain a specific value
     * @param {string|number} address Hexadecimal string or numeric address
     * @param {any} value Value to maintain
     * @param {string} type Data type (default: 'int')
     */
    lock(address, value, type = 'int') {
        const parsedAddr = typeof address === 'string' ? 
            ptr(address) : 
            ptr(address.toString());
        
        const id = lockCounter++;
        lockIndex.push(id);
        
        // Write initial value
        this.write(parsedAddr, value, type);
        
        // Set interval
        const intervalId = setInterval(() => {
            try {
                this.write(parsedAddr, value, type);
            } catch (e) {
                console.error(`Lock ${id} error: ${e.message}`);
                this.unlock(id);
            }
        }, 100);
        
        locks[id] = {
            id,
            address: parsedAddr,
            value,
            type,
            intervalId,
            createdAt: new Date()
        };
        
        console.log(`Memory lock set #${id}: ${parsedAddr} = ${value} (${type})`);
        return id;
    },
    
    /**
     * Unlock a memory lock
     * @param {number} id Lock ID
     */
    unlock(id) {
        if (!locks[id]) {
            console.error(`No lock found for ID ${id}`);
            return false;
        }
        
        clearInterval(locks[id].intervalId);
        
        const idx = lockIndex.indexOf(id);
        if (idx !== -1) {
            lockIndex.splice(idx, 1);
        }
        
        const lock = locks[id];
        delete locks[id];
        
        console.log(`Memory lock released #${id}: ${lock.address}`);
        return true;
    },

    /**
     * Display all memory locks
     */
    list() {
        console.log('\n----- Memory watch list -----');
        
        // Display lock list
        if (lockIndex.length > 0) {
            console.log('\n[Lock list]');
            for (const id of lockIndex) {
                const lock = locks[id];
                console.log(`#${id}: ${lock.address} = ${lock.value} (${lock.type}) - ${formatTime(lock.createdAt)}`);
            }
        }
        
        // Display trace list
        if (traceIndex.length > 0) {
            console.log('\n[Trace list]');
            for (const id of traceIndex) {
                const trace = traces[id];
                console.log(`#${id}: ${trace.address} (${trace.type}) - ${formatTime(trace.createdAt)}`);
            }
        }
        
        // Display watch list
        if (watchIndex.length > 0) {
            console.log('\n[Watch list]');
            for (const id of watchIndex) {
                const watch = watches[id];
                console.log(`#${id}: ${watch.address} (${watch.type}) - ${formatTime(watch.createdAt)}`);
            }
        }
        
        if (lockIndex.length === 0 && traceIndex.length === 0 && watchIndex.length === 0) {
            console.log('No active memory watch.');
        }
        
        console.log('\n-------------------------');
    },

    /**
     * Track a memory address
     * @param {string|number} address Hexadecimal string or numeric address
     * @param {string} type Data type (default: 'int')
     */
    trace(address, type = 'int') {
        const parsedAddr = typeof address === 'string' ? 
            ptr(address) : 
            ptr(address.toString());
        
        const id = traceCounter++;
        traceIndex.push(id);
        
        // Read initial value
        let prevValue;
        try {
            prevValue = this.read(parsedAddr, type);
        } catch (e) {
            console.error(`Error reading initial value: ${e.message}`);
            prevValue = null;
        }
        
        // Set interval
        const intervalId = setInterval(() => {
            try {
                const currentValue = this.read(parsedAddr, type);
                if (JSON.stringify(currentValue) !== JSON.stringify(prevValue)) {
                    console.log(`[Trace #${id}] ${parsedAddr} changed: ${prevValue} → ${currentValue}`);
                    prevValue = currentValue;
                }
            } catch (e) {
                console.error(`Trace ${id} error: ${e.message}`);
                this.untrace(id);
            }
        }, 100);
        
        traces[id] = {
            id,
            address: parsedAddr,
            type,
            intervalId,
            createdAt: new Date()
        };
        
        console.log(`Memory trace set #${id}: ${parsedAddr} (${type})`);
        return id;
    },
    
    /**
     * Stop tracking a memory address
     * @param {number} id Trace ID
     */
    untrace(id) {
        if (!traces[id]) {
            console.error(`No trace found for ID ${id}`);
            return false;
        }
        
        clearInterval(traces[id].intervalId);
        
        const idx = traceIndex.indexOf(id);
        if (idx !== -1) {
            traceIndex.splice(idx, 1);
        }
        
        const trace = traces[id];
        delete traces[id];
        
        console.log(`Memory trace stopped #${id}: ${trace.address}`);
        return true;
    },
    
    /**
     * Watch for value changes in a memory address
     * @param {string|number} address Hexadecimal string or numeric address
     * @param {string} type Data type (default: 'int')
     */
    watch(address, type = 'int') {
        const parsedAddr = typeof address === 'string' ? 
            ptr(address) : 
            ptr(address.toString());
        
        const id = watchCounter++;
        watchIndex.push(id);
        
        // Read initial value
        let prevValue;
        try {
            prevValue = this.read(parsedAddr, type);
        } catch (e) {
            console.error(`Error reading initial value: ${e.message}`);
            prevValue = null;
        }
        
        // Change record
        const changes = [];
        
        // Set interval
        const intervalId = setInterval(() => {
            try {
                const currentValue = this.read(parsedAddr, type);
                if (JSON.stringify(currentValue) !== JSON.stringify(prevValue)) {
                    const timestamp = new Date();
                    const change = {
                        timestamp,
                        from: prevValue,
                        to: currentValue
                    };
                    changes.push(change);
                    console.log(`[Watch #${id}] ${parsedAddr} changed: ${prevValue} → ${currentValue} (${formatTime(timestamp)})`);
                    prevValue = currentValue;
                }
            } catch (e) {
                console.error(`Watch ${id} error: ${e.message}`);
                this.unwatch(id);
            }
        }, 100);
        
        watches[id] = {
            id,
            address: parsedAddr,
            type,
            intervalId,
            changes,
            createdAt: new Date()
        };
        
        console.log(`Memory watch set #${id}: ${parsedAddr} (${type})`);
        return id;
    },
    
    /**
     * Stop watching a memory address and display change summary
     * @param {number} id Watch ID
     */
    unwatch(id) {
        if (!watches[id]) {
            console.error(`No watch found for ID ${id}`);
            return false;
        }
        
        clearInterval(watches[id].intervalId);
        
        const idx = watchIndex.indexOf(id);
        if (idx !== -1) {
            watchIndex.splice(idx, 1);
        }
        
        const watch = watches[id];
        
        console.log(`\n----- Memory watch summary #${id} -----`);
        console.log(`Address: ${watch.address} (${watch.type})`);
        console.log(`Watch start: ${formatTime(watch.createdAt)}`);
        console.log(`Watch end: ${formatTime(new Date())}`);
        console.log(`Change count: ${watch.changes.length}`);
        
        if (watch.changes.length > 0) {
            console.log('\nChange record:');
            watch.changes.forEach((change, index) => {
                console.log(`${index + 1}. ${formatTime(change.timestamp)}: ${change.from} → ${change.to}`);
            });
        } else {
            console.log('\nNo value changes during watch period.');
        }
        
        console.log('\n-------------------------');
        
        delete watches[id];
        
        return true;
    },
};

/**
 * Format a date
 * @param {Date} date Date object
 * @returns {string} Formatted date string
 */
function formatTime(date) {
    return date.toLocaleTimeString('ko-KR', { 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit',
        hour12: false 
    });
}

module.exports = mem; 