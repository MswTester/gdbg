/**
 * Function calling module
 */

const utils = require('./utils');
const log = require('./logger');

const call = {
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

module.exports = call; 