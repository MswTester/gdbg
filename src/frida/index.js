/**
 * gdbg.js - Main entry point
 * frida-compile compatible module
 */

const config = require('./config');
const utils = require('./utils');
const log = require('./logger');
const memory = require('./memory');
const list = require('./list');
const hook = require('./hook');
const scan = require('./scan');
const mem = require('./mem');
const hist = require('./history');
const lib = require('./library');
const call = require('./call');
const cmd = require('./cmd');

// Initialize global state
require('./state');

// Export global aliases and functions
global.help = require('./help');
global.nxt = require('./navigation').nxt;
global.prv = require('./navigation').prv;
global.sav = require('./navigation').sav;
global.sort = require('./navigation').sort;
global.grep = require('./navigation').grep;
global.config = config;

// Export feature-specific modules
global.list = list;
global.hook = hook;
global.call = call;
global.scan = scan;
global.mem = mem;
global.hist = hist;
global.lib = lib;
global.cmd = cmd;

// Register global aliases
global.clss = global.list.class.bind(global.list);
global.meths = global.list.method.bind(global.list);
global.modls = global.list.module.bind(global.list);
global.exps = global.list.export.bind(global.list);
global.hookm = global.hook.method.bind(global.hook);
global.hookn = global.hook.native.bind(global.hook);
global.unhook = global.hook.unhook.bind(global.hook);
global.hooked = global.hook.list.bind(global.hook);
global.calln = global.call.native.bind(global.call);
global.callm = global.call.method.bind(global.call);
global.srch = global.scan.type.bind(global.scan);
global.exct = global.scan.value.bind(global.scan);
global.ls = global.lib.list.bind(global.lib);
global.mv = global.lib.move.bind(global.lib);
global.rm = global.lib.remove.bind(global.lib);
global.r = global.mem.read.bind(global.mem);
global.w = global.mem.write.bind(global.mem);
global.l = global.mem.lock.bind(global.mem);
global.ul = global.mem.unlock.bind(global.mem);
global.v = global.mem.view.bind(global.mem);

// Set up RPC handler for CLI support
(function setupRpcHandler() {
  // Handlers that can be called externally
  rpc.exports = {
    // Execute command
    executeCommand: function(cmd) {
      try {
        // Execute the command
        const result = eval(cmd);
        return {
          status: 'success',
          result: result
        };
      } catch (e) {
        return {
          status: 'error',
          error: e.toString()
        };
      }
    }
  };
})();

// Initial information message
console.log(`
        _____ _____  ____   _____ 
       / ____|  __ \\|  _ \\ / ____|
      | |  __| |  | | |_) | |  __ 
      | | |_ | |  | |  _ <| | |_ |
      | |__| | |__| | |_) | |__| |
       \\_____|_____/|____/ \\_____|
`);
console.log(`
===========================================
    Game Debugger & Memory Tool v${config.version}
          Created by @MswTester
===========================================
`);

log.info('gdbg.js loaded. Type "help" to see available commands.');

// Detect environment
(function detectEnvironment() {
  try {
    if (ObjC.available) {
      log.info('iOS environment detected');
    } else if (Java.available) {
      log.info('Android environment detected');
    }
  } catch (_) {
    // No specific environment detected
  }
})();

// Set up command proxy
(function setupCommandProxy() {
  const originalEval = global.eval;
  global.eval = function(cmd) {
    if (typeof cmd === 'string' && cmd.trim() && 
        !cmd.startsWith('(') && !cmd.startsWith('function')) {
      global.state.commands.push(cmd);
      if (global.state.commands.length > 100) global.state.commands.shift();
    }
    return originalEval.call(this, cmd);
  };
})(); 