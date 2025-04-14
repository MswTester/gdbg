/**
 * 도움말 모듈
 */

const log = require('./logger');

function help(cmd) {
    if (!cmd) {
        log.info('사용 가능한 명령어 (CLI 스타일):');
        console.log('  help [command]            - 이 도움말을 표시합니다');
        console.log('');
        console.log('  list class [pattern]      - Java 클래스 나열');
        console.log('  list method <class> [p]   - 클래스의 메소드 나열');
        console.log('  list module [pattern]     - 로드된 모듈 나열');
        console.log('  list export <mod> [p]     - 모듈의 내보내기 나열');
        console.log('');
        console.log('  mem read <addr> [type]    - 메모리 읽기');
        console.log('  mem write <addr> <val> [t]- 메모리 쓰기');
        console.log('  mem view <addr> [t] [ln]  - 메모리 보기');
        console.log('  mem lock <addr> <val> [t] - 메모리 값 잠금');
        console.log('  mem unlock <index>        - 메모리 잠금 해제');
        console.log('  mem locked                - 잠긴 메모리 목록');
        console.log('  mem trace <addr> [type]   - 메모리 접근 추적');
        console.log('');
        console.log('  scan type <val> [t] [prot]- 메모리에서 값 검색');
        console.log('  scan value <val> [type]   - 특정 값 검색');
        console.log('  scan range <min> <max> [t]- 범위 내 값 검색');
        console.log('  scan increased [type]     - 증가된 값 검색');
        console.log('  scan decreased [type]     - 감소된 값 검색');
        console.log('');
        console.log('  hook method <class.method>- Java 메소드 후킹');
        console.log('  hook native <func>        - 네이티브 함수 후킹');
        console.log('  hook list                 - 후킹된 함수 나열');
        console.log('  hook unhook <index>       - 후킹 해제');
        console.log('');
        console.log('  call native <func> [args] - 네이티브 함수 호출');
        console.log('  call method <m> <idx> [a] - Java 메소드 호출');
        console.log('');
        console.log('  hist save [label]         - 현재 로그 저장');
        console.log('  hist list                 - 저장된 로그 목록');
        console.log('  hist load <index>         - 저장된 로그 로드');
        console.log('  hist clear                - 모든 저장된 로그 삭제');
        console.log('  hist compare <i1> <i2>    - 두 로그 비교');
        console.log('');
        console.log('  lib list [page]           - 라이브러리 항목 보기');
        console.log('  lib save <index> [label]  - 로그 항목을 라이브러리에 저장');
        console.log('  lib clear                 - 라이브러리 비우기');
        console.log('  lib remove <index>        - 라이브러리 항목 제거');
        console.log('  lib move <from> <to>      - 라이브러리 항목 이동');
        console.log('  lib sort [field]          - 라이브러리 항목 정렬');
        console.log('  lib find <pat> [field]    - 라이브러리 항목 검색');
        console.log('  lib export <index>        - 라이브러리 항목 내보내기');
        console.log('  lib duplicate <index>     - 라이브러리 항목 복제');
        console.log('');
        console.log('  cmd history               - 명령어 기록 보기');
        console.log('  cmd alias <name> <cmd>    - 명령어 별칭 생성');
        console.log('');
        console.log('  nxt [page]                - 다음 페이지 이동');
        console.log('  prv [page]                - 이전 페이지 이동');
        console.log('  grep <pattern>            - 로그에서 패턴 검색');
        console.log('  sort [field]              - 로그 정렬');
        return;
    }

    // 명령어별 도움말
    switch(cmd) {
        case 'list':
        case 'list.class':
            log.info('list class [pattern] - Java 클래스 나열');
            console.log('  pattern: 선택사항, 클래스 이름에서 검색할 부분 문자열');
            console.log('예시: list class com.example');
            break;
        case 'list.method':
            log.info('list method <class> [pattern] - 클래스의 메소드 나열');
            console.log('  class: 클래스 인덱스 또는 이름');
            console.log('  pattern: 선택사항, 메소드 이름에서 검색할 부분 문자열');
            console.log('예시: list method 0');
            console.log('      list method com.example.MyClass get');
            break;
        case 'scan':
        case 'scan.type':
            log.info('scan type <value> [type] [prot] - 메모리 스캔');
            console.log('  value: 검색할 값');
            console.log('  type: byte, short, int, uint, float, string (기본값: int)');
            console.log('  prot: 메모리 보호, 예: r--, rw- (기본값: r--)');
            console.log('예시: scan type 12345');
            console.log('      scan type 3.14 float');
            console.log('      scan type "hello" string r--');
            break;
        case 'scan.value':
            log.info('scan value <value> [type] - 특정 값 검색');
            console.log('  value: 검색할 값');
            console.log('  type: 메모리 타입 (기본값: 이전 스캔의 타입)');
            console.log('예시: scan value 100');
            console.log('      scan value 3.14 float');
            break;
        case 'scan.range':
            log.info('scan range <min> <max> [type] - 범위 내 값 검색');
            console.log('  min: 범위의 최소값');
            console.log('  max: 범위의 최대값');
            console.log('  type: 메모리 타입 (기본값: 이전 스캔의 타입)');
            console.log('예시: scan range 100 200');
            console.log('      scan range 1.0 5.0 float');
            break;
        case 'scan.increased':
            log.info('scan increased [type] - 증가된 값 검색');
            console.log('  type: 메모리 타입 (기본값: 이전 스캔의 타입)');
            console.log('설명: 이 명령을 처음 실행하면 현재 값의 스냅샷을 생성합니다.');
            console.log('      두 번째 실행 시 값이 증가한 항목만 표시합니다.');
            console.log('예시: scan increased');
            console.log('      scan increased float');
            break;
        case 'scan.decreased':
            log.info('scan decreased [type] - 감소된 값 검색');
            console.log('  type: 메모리 타입 (기본값: 이전 스캔의 타입)');
            console.log('설명: 이 명령을 처음 실행하면 현재 값의 스냅샷을 생성합니다.');
            console.log('      두 번째 실행 시 값이 감소한 항목만 표시합니다.');
            console.log('예시: scan decreased');
            console.log('      scan decreased float');
            break;
        case 'mem':
        case 'mem.lock':
            log.info('mem lock <addr> <value> [type] - 메모리 값 잠금');
            console.log('  addr: 포인터 인덱스 또는 주소');
            console.log('  value: 잠글 값');
            console.log('  type: 메모리 타입 (기본값: 포인터의 타입)');
            console.log('예시: mem lock 0 100');
            console.log('      mem lock 0x1234ABCD 3.14 float');
            break;
        case 'mem.read':
            log.info('mem read <addr> [type] - 메모리 주소 읽기');
            console.log('  addr: 포인터 인덱스 또는 주소');
            console.log('  type: 메모리 타입 (기본값: uint)');
            console.log('예시: mem read 0');
            console.log('      mem read 0x1234ABCD float');
            break;
        case 'mem.write':
            log.info('mem write <addr> <value> [type] - 메모리 주소에 값 쓰기');
            console.log('  addr: 포인터 인덱스 또는 주소');
            console.log('  value: 쓸 값');
            console.log('  type: 메모리 타입 (기본값: 포인터의 타입)');
            console.log('예시: mem write 0 100');
            console.log('      mem write 0x1234ABCD 3.14 float');
            break;
        case 'mem.view':
            log.info('mem view <addr> [type] [lines] - 메모리 보기');
            console.log('  addr: 포인터 인덱스 또는 주소');
            console.log('  type: 메모리 표현: byte, short, int, uint, float (기본값: byte)');
            console.log('  lines: 표시할 16바이트 라인 수 (기본값: 10)');
            console.log('         포인터 이전 메모리를 표시하려면 음수 사용');
            console.log('예시: mem view 0');
            console.log('      mem view 0x1234ABCD int 20');
            console.log('      mem view 0 float -5');
            break;
        case 'hook':
        case 'hook.method':
            log.info('hook method <class.method> - Java 메소드 후킹');
            console.log('  class.method: 로그 인덱스 또는 "패키지.클래스.메소드" 형식');
            console.log('예시: hook method 0');
            console.log('      hook method com.example.MyClass.doSomething');
            break;
        case 'hook.native':
            log.info('hook native <func> - 네이티브 함수 후킹');
            console.log('  func: 로그 인덱스 또는 함수 주소');
            console.log('예시: hook native 0');
            console.log('      hook native 0x1234ABCD');
            break;
        case 'hook.unhook':
            log.info('hook unhook <index> - 메소드나 함수 후킹 해제');
            console.log('  index: hook list 명령의 후크 인덱스');
            console.log('예시: hook unhook 0');
            break;
        case 'call':
        case 'call.native':
            log.info('call native <func> [args...] - 네이티브 함수 호출');
            console.log('  func: 로그 인덱스 또는 함수 주소');
            console.log('  args: 함수에 전달할 인수');
            console.log('예시: call native 0');
            console.log('      call native 0x1234ABCD 10 20 "문자열"');
            break;
        case 'call.method':
            log.info('call method <method> <idx> [args...] - Java 메소드 호출');
            console.log('  method: 로그 인덱스 또는 "패키지.클래스.메소드" 형식');
            console.log('  idx: 오버로드 인덱스 (보통 0)');
            console.log('  args: 메소드에 전달할 인수');
            console.log('참고: 정적 메소드는 직접 호출됩니다. 비정적 메소드의 경우,');
            console.log('      도구는 클래스의 새 인스턴스를 생성하려고 시도합니다.');
            console.log('예시: call method 0 0');
            console.log('      call method com.example.MyClass.doSomething 0 10 "문자열"');
            break;
        case 'lib':
        case 'lib.save':
            log.info('lib save <index> [label] - 로그 항목을 라이브러리에 저장');
            console.log('  index: 로그 인덱스');
            console.log('  label: 선택사항, 항목에 대한 사용자 정의 레이블');
            console.log('예시: lib save 0');
            console.log('      lib save 0 "중요한 포인터"');
            break;
        case 'grep':
            log.info('grep <pattern> - 정규식으로 결과 필터링');
            console.log('  pattern: 검색할 정규식 패턴');
            console.log('예시: grep function');
            console.log('      grep "0x[0-9A-F]+"');
            break;
        case 'hist':
        case 'hist.compare':
            log.info('hist compare <idx1> <idx2> - 두 이력 항목 비교');
            console.log('  idx1: 첫 번째 이력 인덱스');
            console.log('  idx2: 두 번째 이력 인덱스');
            console.log('예시: hist compare 0 1');
            break;
        case 'cmd':
        case 'cmd.alias':
            log.info('cmd alias <name> <command> - 명령어 별칭 생성');
            console.log('  name: 새 별칭 이름');
            console.log('  command: 실행할 명령어');
            console.log('예시: cmd alias flist list class com.facebook');
            console.log('      cmd alias scanfloat scan type $1 float');
            console.log('참고: $1, $2 등은 별칭 호출 시 인수로 대체됩니다.');
            break;
        default:
            log.warning(`'${cmd}'에 대한 도움말이 없습니다. 모든 명령어를 보려면 help를 사용하세요.`);
    }
}

module.exports = help; 