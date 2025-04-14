#!/usr/bin/env node

const { Command } = require('commander');
const program = new Command();

// Define program information
program
    .name('gdbg') // Replace with your CLI app name
    .description('A simple CLI application using Commander.js')
    .usage('[options] target') // Usage information
    .helpOption('-h, --help', 'Display help information')
    .version("0.3.1", '-v, --version', 'Output the current version') // Version information
    .option('-d, --debug', 'Output extra debugging'); // Global option

program
    .option('-D, --device <ID>', 'connect to device with the given ID') // Option with a value
    .option('-U, --usb', 'connect to USB device') // Option with a value
    .option('-R, --remote', 'connect to remote frida-server') // Option with a value
    .option('-H, --host <HOST>', 'connect to remote frida-server on HOST') // Option with a value

// // Define a command
// program
//     .command('greet')
//     .description('Greets the user')
//     .argument('<name>', 'Name of the person to greet') // Required argument
//     .option('-l, --loud', 'Greet loudly') // Optional flag
//     .action((name, options) => {
//         // Action to perform when the command is executed
//         let greeting = `Hello, ${name}!`;
//         if (options.loud) {
//             greeting = greeting.toUpperCase();
//         }
//         console.log(greeting);
//     });

// Parse the command-line arguments
program.parse(process.argv);

// Handle cases where no command is provided (optional)
if (!process.argv.slice(2).length) {
    program.outputHelp();
}
