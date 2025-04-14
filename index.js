#!/usr/bin/env node

const cli = require('./src/cli');

// CLI 프로그램 생성 및 실행
const program = cli.createProgram();
program.parse(process.argv);

// 명령어가 지정되지 않은 경우 도움말 표시
if (process.argv.length <= 2) {
  program.outputHelp();
}
