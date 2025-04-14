/**
 * Command management module
 */

const log = require('./logger');

const cmd = {
    history() {
        if (!global.state.commands.length) return log.info("No command history");
        global.state.commands.forEach((c, i) => console.log(`${i}: ${c}`));
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

module.exports = cmd; 