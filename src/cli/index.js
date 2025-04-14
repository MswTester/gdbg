/**
 * CLI 모듈의 메인 진입점
 */

const { Command } = require('commander');
const version = require('./version');
const commands = require('../commands');

/**
 * CLI 프로그램 초기화
 * @returns {Command} Commander 프로그램 인스턴스
 */
function createProgram() {
  const program = new Command();
  
  // 프로그램 기본 정보 설정
  program
    .name('gdbg')
    .description('Game Debugger & Memory Analysis Tool')
    .usage('[options] target')
    .helpOption('-h, --help', 'Display help information')
    .version(version.getVersion(), '-v, --version', 'Display version information')
    .option('-d, --debug', 'Output extra debugging information');
  
  // 명령어 등록
  commands.registerAll(program);
  
  return program;
}

module.exports = {
  createProgram
}; 