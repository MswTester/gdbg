/**
 * REPL 명령어 자동완성 모듈
 */

/**
 * 탭 자동완성 설정
 * @param {import('repl').REPLServer} replServer REPL 서버 인스턴스
 */
function setupCompleter(replServer) {
  // 기본 명령어 목록
  const commands = [
    'help',
    'list',
    'hook',
    'scan',
    'trace',
    'find',
    'memory',
    'exit'
  ];

  // 목록 하위 명령어
  const listSubcommands = [
    'class',
    'method',
    'module',
    'export'
  ];

  // 명령어 자동완성 설정
  replServer.completer = function(line) {
    const parts = line.trim().split(' ');
    
    // 첫 번째 단어 자동완성 (기본 명령어)
    if (parts.length === 1) {
      const completions = commands.filter(c => c.startsWith(parts[0]));
      return [completions, parts[0]];
    }
    
    // 두 번째 단어 자동완성 (하위 명령어)
    if (parts.length === 2) {
      if (parts[0] === 'list') {
        const completions = listSubcommands.filter(c => c.startsWith(parts[1]));
        return [completions, parts[1]];
      }
    }
    
    // 기타 자동완성은 현재 지원하지 않음
    return [[], line];
  };
}

module.exports = {
  setupCompleter
}; 