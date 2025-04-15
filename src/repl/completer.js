/**
 * REPL command auto-completion module
 */

/**
 * Setup tab completion
 * @param {import('repl').REPLServer} replServer REPL server instance
 */
function setupCompleter(replServer) {
  // Basic command list
  const commands = [
    'help', 'list', 'mem', 'scan', 'hook',
    'call', 'hist', 'lib', 'cmd', 'nxt',
    'prv', 'grep', 'sav', 'sort', 'exit'
  ];
  
  // List sub-commands
  const subCommands = {
    'list': ['class', 'method', 'module', 'export'],
    'mem': ['read', 'write', 'view', 'lock', 'unlock', 'list', 'trace', 'untrace', 'watch', 'unwatch'],
    'scan': ['type', 'value', 'range', 'increased', 'decreased', 'unchanged', 'changed'],
    'hook': ['method', 'native', 'list', 'unhook'],
    'hist': ['save', 'list', 'load', 'clear', 'compare'],
    'lib': ['list', 'save', 'clear', 'remove', 'move', 'sort', 'find', 'export', 'duplicate']
  };
  
  // Set up command completion
  replServer.completer = function(line) {
    const lineWords = line.split(' ');
    
    // First word completion (basic commands)
    if (lineWords.length === 1) {
      const completions = commands.filter(c => c.startsWith(lineWords[0]));
      return [completions.length ? completions : commands, lineWords[0]];
    }
    
    // Second word completion (sub-commands)
    if (lineWords.length === 2) {
      const cmd = lineWords[0];
      const sub = lineWords[1];
      
      if (subCommands[cmd]) {
        const completions = subCommands[cmd].filter(c => c.startsWith(sub));
        return [completions.length ? completions : subCommands[cmd], sub];
      }
    }
    
    // Other completions are not currently supported
    return [[], line];
  };
}

module.exports = {
  setupCompleter
}; 