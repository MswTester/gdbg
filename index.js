#!/usr/bin/env node

const cli = require('./src/cli');

// Create and run CLI program
const program = cli.createProgram();
program.parse(process.argv);

// Display help if no command is specified
if (process.argv.length <= 2) {
  program.outputHelp();
}
