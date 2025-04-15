/**
 * Main entry point for the CLI module
 */

const { Command } = require('commander');
const version = require('./version');
const commands = require('../commands');

/**
 * Initialize CLI program
 * @returns {Command} Commander program instance
 */
function createProgram() {
  const program = new Command();
  
  // Set up program basic information
  program
    .name('gdbg')
    .description('Game Debugger & Memory Analysis Tool')
    .usage('[options] target')
    .helpOption('-h, --help', 'Display help information')
    .version(version.getVersion(), '-v, --version', 'Display version information')
    .option('-d, --debug', 'Output extra debugging information');
  
  // Register commands
  commands.registerAll(program);
  
  return program;
}

module.exports = {
  createProgram
}; 