/**
 * Logging system module
 */


// Logging system
const log = {
    debug(msg) {
        console.log(`[DEBUG] ${msg}`);
    },
    
    info(msg) {
        console.log(`[INFO] ${msg}`);
    },
    
    warning(msg) {
        console.log(`[WARN] ${msg}`);
    },
    
    error(msg) {
        console.error(`[ERROR] ${msg}`);
    },
    
    success(msg) {
        console.log(`[SUCCESS] ${msg}`);
    },
    
    plain(msg) {
        console.log(msg);
    },
    
    dump(obj) {
        if (!obj) {
            this.info('No data to display');
            return;
        }
        
        // Simplified output for all environments
        console.log(JSON.stringify(obj, null, 2));
    }
};

module.exports = log; 