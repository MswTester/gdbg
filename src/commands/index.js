/**
 * 명령어 모듈 관리
 */

const fridaCommands = require('./frida');
const replCommands = require('./repl');

/**
 * 모든 명령어를 프로그램에 등록
 * @param {import('commander').Command} program Commander 프로그램 인스턴스
 */
function registerAll(program) {
  // Frida 관련 명령어 등록
  fridaCommands.register(program);
  
  // REPL 관련 명령어 등록
  replCommands.register(program);
  
  return program;
}

module.exports = {
  registerAll,
  frida: fridaCommands,
  repl: replCommands
}; 