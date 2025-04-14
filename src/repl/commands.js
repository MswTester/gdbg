/**
 * REPL 명령어 등록 모듈
 */

/**
 * REPL 서버에 명령어 등록
 * @param {import('repl').REPLServer} replServer REPL 서버 인스턴스
 */
function registerCommands(replServer) {
  // 종료 명령어 정의
  replServer.defineCommand('exit', {
    help: '세션을 종료하고 프로그램을 닫습니다',
    action: () => {
      console.log('종료 중...');
      replServer.close();
    }
  });

  // 도움말 명령어 정의
  replServer.defineCommand('help', {
    help: '사용 가능한 명령어에 대한 도움말을 표시합니다',
    action: () => {
      console.log('사용 가능한 명령어:');
      console.log('  help                        - 이 도움말을 표시합니다');
      console.log('  list class [pattern]        - 클래스 목록을 표시합니다');
      console.log('  list method <class> [p]     - 클래스의 메소드 목록을 표시합니다');
      console.log('  list module [pattern]       - 모듈 목록을 표시합니다');
      console.log('  list export <mod> [p]       - 모듈의 내보내기 목록을 표시합니다');
      console.log('');
      console.log('  mem read <address> [type]   - 메모리 주소의 값을 읽습니다');
      console.log('  mem write <addr> <val> [t]  - 메모리 주소에 값을 씁니다');
      console.log('  mem view <addr> [t] [lines] - 메모리 주소를 검사합니다');
      console.log('  mem lock <addr> <val> [t]   - 메모리 주소의 값을 고정합니다');
      console.log('  mem unlock <index>          - 메모리 주소의 잠금을 해제합니다');
      console.log('  mem locked                  - 잠긴 메모리 목록을 표시합니다');
      console.log('  mem trace <addr> [type]     - 메모리 주소의 접근을 추적합니다');
      console.log('');
      console.log('  scan type <val> [t] [prot]  - 메모리에서 값을 검색합니다');
      console.log('  scan value <val> [type]     - 특정 값을 검색합니다');
      console.log('  scan range <min> <max> [t]  - 범위 내 값을 검색합니다');
      console.log('  scan increased [type]       - 증가된 값을 검색합니다');
      console.log('  scan decreased [type]       - 감소된 값을 검색합니다');
      console.log('');
      console.log('  hook method <class.method>  - 자바 메소드를 후킹합니다');
      console.log('  hook native <func>          - 네이티브 함수를 후킹합니다');
      console.log('  hook list                   - 후킹된 함수 목록을 표시합니다');
      console.log('  hook unhook <index>         - 후킹을 제거합니다');
      console.log('');
      console.log('  call native <func> [args]   - 네이티브 함수를 호출합니다');
      console.log('  call method <m> <idx> [a]   - 자바 메소드를 호출합니다');
      console.log('');
      console.log('  hist save [label]           - 현재 로그를 저장합니다');
      console.log('  hist list                   - 저장된 로그 목록을 표시합니다');
      console.log('  hist load <index>           - 저장된 로그를 로드합니다');
      console.log('  hist clear                  - 모든 저장된 로그를 지웁니다');
      console.log('  hist compare <idx1> <idx2>  - 두 로그를 비교합니다');
      console.log('');
      console.log('  lib list [page]             - 라이브러리 항목을 표시합니다');
      console.log('  lib save <index> [label]    - 로그 항목을 라이브러리에 저장합니다');
      console.log('  lib clear                   - 라이브러리를 비웁니다');
      console.log('  lib remove <index>          - 라이브러리 항목을 제거합니다');
      console.log('  lib move <from> <to>        - 라이브러리 항목을 이동합니다');
      console.log('  lib sort [field]            - 라이브러리 항목을 정렬합니다');
      console.log('  lib find <pattern> [field]  - 라이브러리 항목을 검색합니다');
      console.log('  lib export <index>          - 라이브러리 항목을 로그로 내보냅니다');
      console.log('  lib duplicate <index>       - 라이브러리 항목을 복제합니다');
      console.log('');
      console.log('  cmd history                 - 명령어 기록을 표시합니다');
      console.log('  cmd alias <name> <command>  - 명령어 별칭을 생성합니다');
      console.log('');
      console.log('  nxt [page]                  - 다음 페이지로 이동합니다');
      console.log('  prv [page]                  - 이전 페이지로 이동합니다');
      console.log('  grep <pattern>              - 현재 로그에서 패턴을 검색합니다');
      console.log('  sort [field]                - 현재 로그를 정렬합니다');
      console.log('');
      console.log('  exit                        - REPL 세션을 종료합니다');
      replServer.displayPrompt();
    }
  });
}

module.exports = {
  registerCommands
}; 