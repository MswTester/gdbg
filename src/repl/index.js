/**
 * REPL 모듈의 메인 진입점
 */

const repl = require('repl');
const commandEvaluator = require('./evaluator');
const completer = require('./completer');
const commands = require('./commands');

/**
 * REPL 세션 시작
 * @param {any} session Frida 세션
 * @param {any} script 로드된 Frida 스크립트
 */
function startRepl(session, script) {
  // REPL 생성
  const replServer = repl.start({
    prompt: 'gdbg> ',
    eval: commandEvaluator.createEvaluator(script)
  });

  // 명령어 등록
  commands.registerCommands(replServer);

  // 탭 완성 설정
  completer.setupCompleter(replServer);

  // 스크립트를 REPL 컨텍스트에 노출
  replServer.context.script = script;
  replServer.context.session = session;

  // 종료 이벤트 처리
  replServer.on('exit', () => {
    console.log('REPL 세션을 종료합니다...');
    if (session) session.detach();
    process.exit(0);
  });

  // 스크립트 관련 이벤트 처리
  script.message.connect((message) => {
    if (message.type === 'error') {
      console.error('스크립트 오류:', message.description);
    }
  });
  
  // 스크립트가 종료되면 REPL도 종료
  script.destroyed.connect(() => {
    console.log('스크립트 세션이 종료되었습니다. REPL을 종료합니다...');
    replServer.close();
    if (session) session.detach();
    process.exit(0);
  });

  return replServer;
}

module.exports = {
  startRepl
}; 