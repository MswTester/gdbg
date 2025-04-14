/**
 * Library management module
 */

const utils = require('./utils');
const log = require('./logger');
const config = require('./config');

const lib = {
    // Save current log item to library (alias available as global.sav)
    save: function(i, offset) {
        // Use navigation.sav implementation which is exposed as global.sav
        if (global.sav) {
            global.sav(i, offset);
        } else {
            log.error("Cannot access sav function");
        }
    },
    
    // List library items with pagination
    list(page = 0, size = config.pageSize) {
        if (!global.state.lib.length) return log.error("ls(): No values in lib");
        
        const start = page * size;
        const end = Math.min(start + size, global.state.lib.length);
        
        if (start >= global.state.lib.length) {
            return log.error(`ls(): Page ${page} exceeds available items (total: ${global.state.lib.length})`);
        }
        
        log.info(`Library items ${start}-${end-1} / ${global.state.lib.length}`);
        const items = global.state.lib.slice(start, end);
        
        log.table(items, (item, idx) => 
            `[${start + idx}] ${item.label} (${item.type})`
        );
        
        if (end < global.state.lib.length) {
            log.info(`Use ls(${page + 1}) to see the next page`);
        }
    },
    
    // Clear all library items
    clear() {
        if (!global.state.lib.length) return log.info("Library is already empty");
        const count = global.state.lib.length;
        global.state.lib.length = 0;
        log.success(`Cleared ${count} items from library`);
    },
    
    // Remove an item by index
    remove(idx) {
        if (idx < 0 || idx >= global.state.lib.length) {
            return log.error(`lib.remove(): Invalid index ${idx}`);
        }
        
        const removed = global.state.lib.splice(idx, 1)[0];
        log.success(`Removed lib[${idx}]: ${removed.label}`);
        
        // Reindex remaining items
        global.state.lib.forEach((item, i) => {
            if (item.index !== undefined) item.index = i;
        });
    },
    
    // Move an item from one index to another
    move(fromIdx, toIdx) {
        if (fromIdx < 0 || fromIdx >= global.state.lib.length) {
            return log.error(`lib.move(): Invalid source index ${fromIdx}`);
        }
        
        if (toIdx < 0 || toIdx >= global.state.lib.length) {
            return log.error(`lib.move(): Invalid target index ${toIdx}`);
        }
        
        if (fromIdx === toIdx) {
            return log.info(`Item is already at index ${fromIdx}`);
        }
        
        // Get item to move
        const item = global.state.lib[fromIdx];
        
        // Remove the item
        global.state.lib.splice(fromIdx, 1);
        
        // Insert at new position
        global.state.lib.splice(toIdx, 0, item);
        
        // Reindex all items
        global.state.lib.forEach((item, i) => {
            if (item.index !== undefined) item.index = i;
        });
        
        log.success(`Moved item from lib[${fromIdx}] to lib[${toIdx}]`);
    },
    
    // Sort library items by specific field
    sort(field = 'label') {
        if (!global.state.lib.length) return log.error("lib.sort(): Library is empty");
        
        try {
            const sorted = [...global.state.lib];
            
            if (field === 'label' || field === 'type') {
                sorted.sort((a, b) => a[field].localeCompare(b[field]));
            } else if (field === 'index') {
                sorted.sort((a, b) => (a.index || 0) - (b.index || 0));
            } else if (field === 'address' && sorted[0]?.value?.address) {
                sorted.sort((a, b) => a.value.address.toString().localeCompare(b.value.address.toString()));
            } else {
                return log.error(`lib.sort(): Unsupported field "${field}"`);
            }
            
            global.state.lib = sorted;
            
            // Reindex all items
            global.state.lib.forEach((item, i) => {
                if (item.index !== undefined) item.index = i;
            });
            
            log.success(`Sorted library by ${field}`);
            this.list();
        } catch (e) {
            log.error(`lib.sort() failed: ${e}`);
        }
    },
    
    // Find items in library matching a pattern
    find(pattern, field = 'label') {
        if (!global.state.lib.length) return log.error("lib.find(): Library is empty");
        
        if (typeof pattern === 'string') {
            pattern = pattern.toLowerCase();
        }
        
        const results = global.state.lib.filter(item => {
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
            `[${global.state.lib.indexOf(item)}] ${item.label} (${item.type})`
        );
        
        return results;
    },
    
    // Export item from library to log
    export(idx) {
        if (idx < 0 || idx >= global.state.lib.length) {
            return log.error(`lib.export(): Invalid index ${idx}`);
        }
        
        const item = global.state.lib[idx];
        global.state.logs.push({ ...item, index: global.state.logs.length });
        log.success(`Exported lib[${idx}] to logs[${global.state.logs.length - 1}]`);
        return global.state.logs.length - 1;
    },
    
    // Create a copy of an item
    duplicate(idx) {
        if (idx < 0 || idx >= global.state.lib.length) {
            return log.error(`lib.duplicate(): Invalid index ${idx}`);
        }
        
        const item = global.state.lib[idx];
        global.state.lib.push({ ...item });
        log.success(`Duplicated lib[${idx}] to lib[${global.state.lib.length - 1}]`);
        return global.state.lib.length - 1;
    }
};

module.exports = lib; 