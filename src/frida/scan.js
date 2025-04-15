/**
 * Memory scanning module
 */

const utils = require('./utils');
const log = require('./logger');
const config = require('./config');
const memory = require('./memory');
const list = require('./list');

const scan = {
    /**
     * Scan memory for a specified type and value
     * @param {any} val Value to search for
     * @param {string} t Data type to search
     * @param {string} p Memory protection type
     * @returns {Array} Array of found addresses
     */
    type(val, t = config.defaultScanType, p = 'r-x') {
        t = t || config.defaultScanType;
        p = p || 'r-x';
        global.state.logs.length = 0;
        global.state.lastScanType = t;
        let idx = 0, count = 0;
        try {
            // Validate value type and log
            const type = t.toLowerCase();
            log.info(`Scanning for ${val} (type: ${type}, protection: ${p})`);
            
            // Create pattern
            const pattern = utils.valueToPattern(val, type);
            if (!pattern) {
                return log.error('Invalid value or type for pattern generation');
            }
            
            // Perform memory scan
            const ranges = Process.enumerateRangesSync({protection: p});
            log.info(`Scanning ${ranges.length} memory ranges...`);
            
            const results = [];
            for (const range of ranges) {
                try {
                    const matches = Memory.scanSync(range.base, range.size, pattern);
                    if (matches.length > 0) {
                        for (const match of matches) {
                            results.push({
                                address: match.address,
                                value: val,
                                type: type
                            });
                        }
                    }
                } catch (e) {
                    // Skip ranges that can't be read
                }
            }
            
            log.success(`Search completed: found ${results.length} results`);
            global.state.lastSearch = results;
            global.state.searchHistory.push(results);
            return results;
        } catch (e) {
            log.error(`Scan error: ${e.message}`);
            return [];
        }
    },

    /**
     * Filter previous scan results with a condition
     * @param {Function} cond Filtering condition function
     * @param {string} t Data type
     * @returns {Array} Filtered results
     */
    next(cond, t = global.state.lastScanType) {
        if (!global.state.lastSearch || global.state.lastSearch.length === 0) {
            log.error('No previous search results to filter');
            return [];
        }
        
        try {
            const memory = require('./memory');
            const results = [];
            const type = t.toLowerCase();
            
            for (const result of global.state.lastSearch) {
                try {
                    const currentValue = memory.reader[type](result.address);
                    if (cond(currentValue, result.value)) {
                        results.push({
                            address: result.address,
                            value: currentValue,
                            type: type
                        });
                    }
                } catch (e) {
                    // Skip addresses that can't be read
                }
            }
            
            log.success(`Filter completed: ${results.length} results from ${global.state.lastSearch.length} previous results`);
            global.state.lastSearch = results;
            global.state.searchHistory.push(results);
            return results;
        } catch (e) {
            log.error(`Filter error: ${e.message}`);
            return [];
        }
    },
    
    /**
     * Search for exact value
     * @param {any} val Value to search for
     * @param {string} t Data type
     * @returns {Array} Search results
     */
    value(val, t = 'int') {
        // Check if string can be converted to number
        if (typeof val === 'string' && !isNaN(Number(val))) {
            val = Number(val);
        }
        
        return this.next((currentVal) => currentVal === val, t);
    },
    
    /**
     * Search for values within a range
     * @param {number} min Minimum value
     * @param {number} max Maximum value
     * @param {string} t Data type
     * @returns {Array} Search results
     */
    range(min, max, t = 'int') {
        // Check if string can be converted to number
        if (typeof min === 'string' && !isNaN(Number(min))) {
            min = Number(min);
        }
        if (typeof max === 'string' && !isNaN(Number(max))) {
            max = Number(max);
        }
        
        return this.next((currentVal) => currentVal >= min && currentVal <= max, t);
    },
    
    /**
     * Search for increased values
     * @param {string} t Data type
     * @returns {Array} Search results
     */
    increased(t = 'int') {
        if (!global.state.lastCompare) {
            // First run - save current values
            log.info('Taking snapshot of current values. Run command again after value increases.');
            
            const memory = require('./memory');
            const prevValues = {};
            const results = global.state.lastSearch || [];
            
            for (const result of results) {
                try {
                    prevValues[result.address] = memory.reader[t](result.address);
                } catch (e) {
                    // Skip addresses that can't be read
                }
            }
            
            global.state.lastCompare = prevValues;
            return results;
        } else {
            return this.next((currentVal, prevVal) => currentVal > global.state.lastCompare[prevVal.address], t);
        }
    },
    
    /**
     * Search for decreased values
     * @param {string} t Data type
     * @returns {Array} Search results
     */
    decreased(t = 'int') {
        if (!global.state.lastCompare) {
            // First run - save current values
            log.info('Taking snapshot of current values. Run command again after value decreases.');
            
            const memory = require('./memory');
            const prevValues = {};
            const results = global.state.lastSearch || [];
            
            for (const result of results) {
                try {
                    prevValues[result.address] = memory.reader[t](result.address);
                } catch (e) {
                    // Skip addresses that can't be read
                }
            }
            
            global.state.lastCompare = prevValues;
            return results;
        } else {
            return this.next((currentVal, prevVal) => currentVal < global.state.lastCompare[prevVal.address], t);
        }
    }
};

module.exports = scan; 