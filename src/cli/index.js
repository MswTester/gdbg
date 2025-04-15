/**
 * Main entry point for the CLI module
 */

const { Command } = require('commander');
const version = require('./version');
const commands = require('../commands');
const frida = require('frida');
const fs = require('fs');
const path = require('path');
const replModule = require('../repl');

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
    .usage('[options] [command]')
    .helpOption('-h, --help', 'Display help information')
    .version(version.getVersion(), '-v, --version', 'Display version information')
    .option('-d, --debug', 'Output extra debugging information')
    // Add Frida attachment options
    .option('-U, --usb', 'Connect to USB device')
    .option('-R, --remote [host:port]', 'Connect to remote frida-server')
    .option('-L, --local', 'Connect to local system')
    .option('-D, --device <id>', 'Connect to device with the given ID')
    .option('-n, --name <process>', 'Connect to process with the given name')
    .option('-p, --pid <pid>', 'Connect to process with the given PID')
    .option('-f, --spawn <program>', 'Spawn the specified program and attach to it');
  
  // Register commands
  commands.registerAll(program);
  
  // Default action when no command is provided (attempt to attach)
  program.action(async (options) => {
    // Only run default action if attachment options are provided
    if (options.usb || options.remote || options.local || options.device || 
        options.name || options.pid || options.spawn) {
      await attachToProcess(options);
    }
  });
  
  return program;
}

/**
 * Connect to a process via Frida and start REPL
 * @param {Object} options Connection options
 */
async function attachToProcess(options) {
  try {
    // Validate options
    if (!options.usb && !options.remote && !options.local && !options.device) {
      console.error('Error: No device option provided (-U, -R, -L, or -D)');
      return;
    }
    
    if (!options.name && !options.pid && !options.spawn) {
      console.error('Error: No target specified (-n, -p, or -f)');
      return;
    }
    
    let device, session;
    
    // Connect to target process using Frida
    if (options.usb) {
      device = await frida.getUsbDevice();
    } else if (options.remote) {
      const parts = options.remote === true ? [] : options.remote.split(':');
      const host = parts[0] || 'localhost';
      const port = parts[1] ? parseInt(parts[1]) : 27042;
      device = await frida.getRemoteDevice({ host, port });
    } else if (options.local) {
      device = await frida.getLocalDevice();
    } else if (options.device) {
      device = await frida.getDevice(options.device);
    }
    
    if (options.name) {
      session = await device.attach(options.name);
    } else if (options.pid) {
      session = await device.attach(parseInt(options.pid));
    } else if (options.spawn) {
      const pid = await device.spawn(options.spawn);
      session = await device.attach(pid);
      await device.resume(pid);
    }
    
    console.log('Connected to target process.');
    
    // Load GDBG script
    const scriptPath = path.join(__dirname, '../../gdbg.js');
    const scriptSource = fs.readFileSync(scriptPath, 'utf-8');
    const script = await session.createScript(scriptSource);
    
    // Handle script messages
    script.message.connect((message) => {
      if (message.type === 'send') {
        console.log(message.payload);
      } else if (message.type === 'error') {
        console.error('Script error:', message.stack);
      }
    });
    
    await script.load();
    
    // Start REPL session
    replModule.startRepl(session, script);
  } catch (error) {
    console.error('Error:', error.message);
    if (error.stack) console.error(error.stack);
  }
}

module.exports = {
  createProgram
}; 