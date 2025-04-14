/**
 * REPL 관련 명령어 모듈
 */

const replModule = require('../repl');

/**
 * REPL 관련 명령어 등록
 * @param {import('commander').Command} program Commander 프로그램 인스턴스
 */
function register(program) {
  // REPL 전용 명령어는 현재 구현되어 있지 않음
  // 필요에 따라 확장 가능
}

module.exports = {
  register
}; 