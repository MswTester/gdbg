#!/usr/bin/env node

const { Command } = require('commander');
const frida = require('frida');
const repl = require('repl');
const fs = require('fs');
const chalk = require('chalk');
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
    .option('-f, --file <TARGET>', 'spawn FILE') // Option with a value
    .option('-n, --attach-name <NAME>', 'attach to NAME') // Option with a value
    .option('-p, --pid <PID>', 'attach to process with PID') // Option with a value
    .description('Connect to a target process using Frida and start a REPL session')
    .action(async (options) => {
        // Check if any of the options are provided
        if (!options.device && !options.usb && !options.remote && !options.host) {
            console.error('Error: No device option provided.');
            program.outputHelp();
            process.exit(1);
        }
        if (!options.file && !options.attachName && !options.pid) {
            console.error('Error: No target specified.');
            program.outputHelp();
            process.exit(1);
        }

        // Connect to the target process using Frida
        let session;
        try {
            const device = await (
                options.usb ? frida.getUsbDevice() :
                options.remote ? frida.getRemoteDevice() :
                options.host ? frida.getDeviceManager().addRemoteDevice(options.host) :
                options.device ? frida.getDevice(options.device) :
                frida.getLocalDevice()
            )
            if(options.file) {
                const pid = await device.spawn(options.file);
                session = await device.attach(pid);
            } else {
                session = await device.attach(options.attachName || +options.pid);
            }
            console.log('Connected to target process.');
        } catch (error) {
            console.error('Error connecting to target process:', error.message);
            process.exit(1);
        }
        await session.resume();

        const script = await session.createScript(`
            send('Hello from Frida!');
            recv('message', (message) => {
                console.log(message);
            });
            console.log('Script loaded and running.');
        `);
        await script.load();
        const replServer = repl.start({ prompt: 'gdbg>' });

        replServer.defineCommand('exit', {
            action: () => {
                console.log('Exiting...');
                session.detach();
                replServer.close();
            }
        });
    });

// Parse the command-line arguments
program.parse(process.argv);

// Handle cases where no command is provided (optional)
if (!process.argv.slice(2).length) {
    program.outputHelp();
}
