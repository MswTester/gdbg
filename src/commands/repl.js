/**
 * Command module related REPL
 */

const replModule = require('../repl');

/**
 * Register command related REPL
 * @param {import('commander').Command} program Commander program instance
 */
function register(program) {
  // REPL-only commands are not currently implemented
  // Scalable as needed
}

module.exports = {
  register
}; 