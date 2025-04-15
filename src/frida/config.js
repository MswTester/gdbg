/**
 * Configuration module
 */

// Configuration and state management
const CONFIG = {
    version: "0.6.0",
    pageSize: 20,        // Number of items to display per page
    scanInterval: 200,   // Memory scan interval (ms)
    defaultScanType: 'uint',
    colors: {
        enabled: true,   // Enable color logging
        info: '\x1b[36m',    // Cyan
        success: '\x1b[32m',  // Green
        error: '\x1b[31m',    // Red
        warning: '\x1b[33m',  // Yellow
        reset: '\x1b[0m'      // Reset color
    }
};

// Configuration commands
const configCommands = {
    show() {
        const log = require('./logger');
        log.info('Current configuration:');
        console.log(`  Page size: ${CONFIG.pageSize}`);
        console.log(`  Color output: ${CONFIG.colors.enabled ? 'Enabled' : 'Disabled'}`);
        console.log(`  Default scan type: ${CONFIG.defaultScanType}`);
    },
    
    set(key, value) {
        const log = require('./logger');
        if (key === 'pageSize') {
            if (typeof value !== 'number' || value < 1) {
                return log.error('pageSize must be a positive number');
            }
            CONFIG.pageSize = value;
            log.success(`Page size set to ${value}`);
        } else if (key === 'colors') {
            CONFIG.colors.enabled = !!value;
            log.success(`Color output ${value ? 'enabled' : 'disabled'}`);
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

module.exports = Object.assign({}, CONFIG, configCommands); 