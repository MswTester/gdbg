/**
 * Main entry point for the REPL module
 */

const repl = require('repl');
const commandEvaluator = require('./evaluator');
const completer = require('./completer');
const commands = require('./commands');

/**
 * Start REPL session
 * @param {any} session Frida session
 * @param {any} script Loaded Frida script
 */
function startRepl(session, script) {
  // Create REPL
  const replServer = repl.start({
    prompt: 'gdbg> ',
    eval: commandEvaluator.createEvaluator(script)
  });

  // Register commands
  commands.registerCommands(replServer);

  // Set up tab completion
  completer.setupCompleter(replServer);

  // Expose script to REPL context
  replServer.context.script = script;
  replServer.context.session = session;

  // Handle exit event
  replServer.on('exit', () => {
    console.log('Terminating GDBG session...');
    if (session) session.detach();
    process.exit(0);
  });

  // Handle script-related events
  script.message.connect((message) => {
    if (message.type === 'error') {
      console.error('Script error:', message.description);
    }
  });
  
  // Terminate REPL when script is terminated
  script.destroyed.connect(() => {
    console.log('Script session terminated. Exiting GDBG...');
    replServer.close();
    if (session) session.detach();
    process.exit(0);
  });

  return replServer;
}

module.exports = {
  startRepl
}; 