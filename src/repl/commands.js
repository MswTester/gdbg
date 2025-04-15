/**
 * REPL command registration module
 */

/**
 * Register commands to the REPL server
 * @param {import('repl').REPLServer} replServer REPL server instance
 */
function registerCommands(replServer) {
  // Currently no additional commands need to be registered
  // Command execution is handled by the evaluator
}

module.exports = {
  registerCommands
}; 