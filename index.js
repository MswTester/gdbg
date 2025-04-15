#!/usr/bin/env node

const cli = require('./src/cli');

// Create and run CLI program
const program = cli.createProgram();
program.parse(process.argv);

// Only show help if no arguments provided and no default action was triggered
if (process.argv.length <= 2 && !program.opts().usb && !program.opts().remote && 
    !program.opts().local && !program.opts().device) {
  program.outputHelp();
}
