/**
 * Frida-related command module
 */

const frida = require('frida');

/**
 * Register Frida-related commands
 * @param {import('commander').Command} program Commander program instance
 */
function register(program) {
  // Add ps command to list processes like frida-ps
  const psCommand = program.command('ps')
    .description('List processes (like frida-ps)')
    .option('-U, --usb', 'Connect to USB device')
    .option('-R, --remote [host:port]', 'Connect to remote frida-server')
    .option('-L, --local', 'Connect to local system (default)')
    .option('-D, --device <id>', 'Connect to device with the given ID')
    .option('-a, --all', 'Include all processes')
    .option('-i, --applications', 'Include only applications')
    .option('-j, --json', 'Output as JSON')
    .action(async (options) => {
      try {
        // Determine device
        let device;
        
        if (options.usb) {
          device = await frida.getUsbDevice();
        } else if (options.remote) {
          const parts = options.remote === true ? [] : options.remote.split(':');
          const host = parts[0] || 'localhost';
          const port = parts[1] ? parseInt(parts[1]) : 27042;
          device = await frida.getRemoteDevice({ host, port });
        } else if (options.device) {
          device = await frida.getDevice(options.device);
        } else {
          // Default to local if no device option specified
          device = await frida.getLocalDevice();
        }
        
        // Get process list with appropriate filters
        let applications = options.applications || false;
        let scope = applications ? 'application' : (options.all ? 'full' : 'minimal');
        const processes = await device.enumerateProcesses({ scope });
        
        // Display results
        if (options.json) {
          console.log(JSON.stringify(processes, null, 2));
        } else {
          console.log('PID\tName');
          console.log('---\t----');
          processes.forEach(process => {
            console.log(`${process.pid}\t${process.name}`);
          });
        }
      } catch (error) {
        console.error('Error:', error.message);
        if (error.stack) console.error(error.stack);
      }
    });
  
  return program;
}

module.exports = {
  register
}; 