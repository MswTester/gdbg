/**
 * Command module management
 */

const fridaCommands = require('./frida');
const replCommands = require('./repl');

/**
 * Register all commands to the program
 * @param {import('commander').Command} program Commander program instance
 */
function registerAll(program) {
  // Register Frida-related commands
  fridaCommands.register(program);
  
  // Register REPL-related commands
  replCommands.register(program);
  
  return program;
}

module.exports = {
  registerAll,
  frida: fridaCommands,
  repl: replCommands
}; 