/**
 * Global state management module
 */

const config = require('./config');

// Initialize global state
global.state = {
    logs: [],            // Main log storage
    lib: [],             // Library storage
    hist: [],            // History storage
    locks: [],           // Memory lock storage
    hooks: [],           // Hook storage
    logIndex: 0,         // Current log index
    pageSize: config.pageSize,
    commands: []         // Command history
};

module.exports = global.state; 