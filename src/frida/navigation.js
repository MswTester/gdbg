/**
 * Navigation functions module
 */

const log = require('./logger');
const utils = require('./utils');
const config = require('./config');

// Navigate to a specific index with pagination
function nxt(i = null) {
    const s = config.pageSize;
    const p = i === null ? Math.floor(global.state.logIndex / s) + 1 : parseInt(i);
    global.state.logIndex = p * s;
    
    if (global.state.logs.length > 0) {
        log.info(`Items ${global.state.logIndex + 1}-${Math.min(global.state.logIndex + s, global.state.logs.length)} / ${global.state.logs.length}`);
        displayPage();
        return global.state.logIndex;
    } else {
        log.info('No items to display');
        return 0;
    }
}

// Save an item to the library
function sav(i, label) {
    // When offset is provided, it means saving from memory view
    if (i && i.hasOwnProperty('offset')) {
        const addr = global.state.memViewBase.add(parseInt(i.offset));
        const lib = require('./library');
        return lib.save(addr, label);
    }
    
    const lib = require('./library');
    return lib.save(i, label);
}

// Go to previous page
function prv(i = null) {
    const s = config.pageSize;
    const p = i === null ? Math.floor(global.state.logIndex / s) - 1 : parseInt(i);
    global.state.logIndex = Math.max(0, p * s);
    
    if (global.state.logs.length > 0) {
        log.info(`Items ${global.state.logIndex + 1}-${Math.min(global.state.logIndex + s, global.state.logs.length)} / ${global.state.logs.length}`);
        displayPage();
        return global.state.logIndex;
    } else {
        log.info('No items to display');
        return 0;
    }
}

// Filter logs by pattern
function grep(pattern) {
    if (!pattern || global.state.logs.length === 0) {
        return log.error('No pattern provided or no logs to filter');
    }
    
    try {
        const regex = new RegExp(pattern, 'i');
        const filtered = global.state.logs.filter(item => 
            regex.test(JSON.stringify(item.label)) || 
            regex.test(JSON.stringify(item.value))
        );
        
        if (filtered.length === 0) {
            log.info(`No items matching pattern "${pattern}"`);
            return;
        }
        
        // Save original logs and replace with filtered results
        global.state.originalLogs = global.state.logs;
        global.state.logs = filtered;
        global.state.logIndex = 0;
        
        log.success(`Found ${filtered.length} items matching pattern "${pattern}"`);
        displayPage();
    } catch (e) {
        log.error(`Invalid regex pattern: ${e.message}`);
    }
}

// Sort logs by field
function sort(field = 'index') {
    if (global.state.logs.length === 0) {
        return log.error('No logs to sort');
    }
    
    const fields = {
        'index': (a, b) => a.index - b.index,
        'value': (a, b) => {
            const aVal = typeof a.value === 'object' ? JSON.stringify(a.value) : a.value;
            const bVal = typeof b.value === 'object' ? JSON.stringify(b.value) : b.value;
            return aVal.localeCompare(bVal);
        },
        'label': (a, b) => a.label.localeCompare(b.label),
        'type': (a, b) => a.type.localeCompare(b.type),
        'address': (a, b) => {
            if (a.value && a.value.address && b.value && b.value.address) {
                return a.value.address.compare(b.value.address);
            }
            return 0;
        }
    };
    
    const sortFn = fields[field] || fields.index;
    global.state.logs.sort(sortFn);
    
    global.state.logIndex = 0;
    log.success(`Sorted logs by ${field}`);
    displayPage();
}

// Display current page of logs
function displayPage() {
    const s = config.pageSize;
    const startIdx = global.state.logIndex;
    const endIdx = Math.min(startIdx + s, global.state.logs.length);
    
    if (startIdx >= global.state.logs.length) {
        log.error('Page index out of range');
        global.state.logIndex = Math.max(0, global.state.logs.length - s);
        return displayPage();
    }
    
    // Display log items
    const items = global.state.logs.slice(startIdx, endIdx);
    const table = items.map(item => {
        let valueStr = '';
        
        if (item.type === 'ptr') {
            valueStr = utils.formatAddress(item.value.address || item.value);
        } else if (typeof item.value === 'object') {
            valueStr = utils.truncate(JSON.stringify(item.value), 80);
        } else {
            valueStr = utils.truncate(String(item.value), 80);
        }
        
        return `[${item.index}] ${item.label}: ${valueStr} (${item.type})`;
    });
    
    console.log(table.join('\n'));
}

module.exports = {
    nxt,
    prv,
    grep,
    sort,
    sav
}; 