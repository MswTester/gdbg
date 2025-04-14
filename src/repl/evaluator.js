/**
 * REPL 명령어 평가기
 */

const repl = require('repl');

/**
 * 명령어 평가기 생성
 * @param {any} script Frida 스크립트
 * @returns {Function} 명령어 평가 함수
 */
function createEvaluator(script) {
  return async function(cmd, context, filename, callback) {
    cmd = cmd.trim();
    
    if (!cmd) {
      return callback(null);
    }
    
    // 명령어 파싱 (따옴표 지원)
    const parts = parseCommand(cmd);
    const command = parts[0];
    const args = parts.slice(1);
    
    try {
      await executeCommand(script, command, args);
      callback(null);
    } catch (e) {
      callback(new repl.Recoverable(e));
    }
  };
}

/**
 * 명령어 문자열을 파싱하여 인자 배열로 변환 (따옴표 내 공백 지원)
 * @param {string} cmdStr 명령어 문자열
 * @returns {string[]} 파싱된 인자 배열
 */
function parseCommand(cmdStr) {
  const result = [];
  let current = '';
  let inQuotes = false;
  let quoteChar = '';
  
  for (let i = 0; i < cmdStr.length; i++) {
    const char = cmdStr[i];
    
    // 따옴표 처리
    if ((char === '"' || char === "'") && (i === 0 || cmdStr[i-1] !== '\\')) {
      if (!inQuotes) {
        inQuotes = true;
        quoteChar = char;
      } else if (char === quoteChar) {
        inQuotes = false;
      } else {
        current += char;
      }
      continue;
    }
    
    // 공백 처리
    if (char === ' ' && !inQuotes) {
      if (current) {
        result.push(current);
        current = '';
      }
      continue;
    }
    
    current += char;
  }
  
  if (current) {
    result.push(current);
  }
  
  return result;
}

/**
 * 16진수 주소 문자열인지 확인
 * @param {string} str 확인할 문자열
 * @returns {boolean} 16진수 주소 여부
 */
function isHexAddress(str) {
  return /^0x[0-9a-fA-F]+$/.test(str);
}

/**
 * 16진수 주소 문자열을 ptr() 호출로 변환
 * @param {string} addr 16진수 주소 문자열
 * @returns {string} 변환된 JS 코드
 */
function convertHexAddress(addr) {
  if (isHexAddress(addr)) {
    return `ptr("${addr}")`;
  }
  return addr;
}

/**
 * 명령어 실행
 * @param {any} script Frida 스크립트
 * @param {string} cmd 명령어
 * @param {string[]} args 명령어 인자
 */
async function executeCommand(script, cmd, args) {
  try {
    let jsCode = '';
    
    switch(cmd) {
      // 기본 명령어
      case 'help':
        if (args.length === 0) {
          showHelp();
          return;
        }
        jsCode = `help(${JSON.stringify(args[0])})`;
        break;
        
      // 목록 명령어
      case 'list':
        if (args.length === 0) {
          console.error('사용법: list <type> [pattern]');
          console.error('타입: class, method, module, export');
          return;
        }
        
        const listType = args[0];
        const listArgs = args.slice(1);
        
        switch(listType) {
          case 'class':
            jsCode = `clss(${listArgs.length > 0 ? JSON.stringify(listArgs[0]) : ''})`;
            break;
          case 'method':
            if (listArgs.length === 0) {
              console.error('사용법: list method <class> [pattern]');
              return;
            }
            jsCode = `meths(${JSON.stringify(listArgs[0])}, ${listArgs.length > 1 ? JSON.stringify(listArgs[1]) : ''})`;
            break;
          case 'module':
            jsCode = `modls(${listArgs.length > 0 ? JSON.stringify(listArgs[0]) : ''})`;
            break;
          case 'export':
            if (listArgs.length === 0) {
              console.error('사용법: list export <module> [pattern]');
              return;
            }
            jsCode = `exps(${JSON.stringify(listArgs[0])}, ${listArgs.length > 1 ? JSON.stringify(listArgs[1]) : ''})`;
            break;
          default:
            console.error(`알 수 없는 목록 유형: ${listType}`);
            return;
        }
        break;
        
      // 메모리 조작 명령어
      case 'mem':
        if (args.length < 2) {
          console.error('사용법: mem <동작> [인수...]');
          console.error('동작 목록: read, write, view, lock, unlock, list, watch, unwatch, trace, untrace');
          return;
        }
        
        const action = args[1];
        
        switch(action) {
          case 'read':
            if (args.length === 0) {
              console.error('사용법: mem read <address> [type]');
              return;
            }
            // 16진수 주소 처리
            const addrRead = isHexAddress(args[0]) ? convertHexAddress(args[0]) : JSON.stringify(args[0]);
            jsCode = `mem.read(${addrRead}, ${args.length > 1 ? JSON.stringify(args[1]) : ''})`;
            break;
          case 'write':
            if (args.length < 2) {
              console.error('사용법: mem write <address> <value> [type]');
              return;
            }
            // 16진수 주소 처리
            const addrWrite = isHexAddress(args[0]) ? convertHexAddress(args[0]) : JSON.stringify(args[0]);
            jsCode = `mem.write(${addrWrite}, ${JSON.stringify(args[1])}, ${args.length > 2 ? JSON.stringify(args[2]) : ''})`;
            break;
          case 'view':
            if (args.length === 0) {
              console.error('사용법: mem view <address> [type] [lines]');
              return;
            }
            // 16진수 주소 처리
            const addrView = isHexAddress(args[0]) ? convertHexAddress(args[0]) : JSON.stringify(args[0]);
            jsCode = `mem.view(${addrView}, ${args.length > 1 ? JSON.stringify(args[1]) : ''}, ${args.length > 2 ? args[2] : ''})`;
            break;
          case 'lock':
            if (args.length < 4) {
              console.error('사용법: mem lock <주소> <값> [타입]');
              return;
            }
            const addr = args[2];
            const value = args[3];
            const type = args[4] || 'int';
            
            jsCode = `mem.lock(${addr}, ${value}, ${type})`;
            break;
          case 'unlock':
            if (args.length < 3) {
              console.error('사용법: mem unlock <id>');
              return;
            }
            const id = parseInt(args[2]);
            
            jsCode = `mem.unlock(${id})`;
            break;
          case 'locked':
            console.info('mem locked는 mem list로 변경되었습니다. 향후 mem list를 사용하세요.');
            jsCode = `mem.list()`;
            break;
          case 'list':
            jsCode = `mem.list()`;
            break;
          case 'trace':
            if (args.length < 3) {
              console.error('사용법: mem trace <주소> [타입]');
              return;
            }
            const addrTrace = isHexAddress(args[2]) ? convertHexAddress(args[2]) : JSON.stringify(args[2]);
            jsCode = `mem.trace(${addrTrace}, ${args.length > 3 ? JSON.stringify(args[3]) : ''})`;
            break;
          case 'untrace':
            if (args.length < 3) {
              console.error('사용법: mem untrace <id>');
              return;
            }
            const idTrace = parseInt(args[2]);
            
            jsCode = `mem.untrace(${idTrace})`;
            break;
          case 'watch':
            if (args.length < 3) {
              console.error('사용법: mem watch <주소> [타입]');
              return;
            }
            const addrWatch = isHexAddress(args[2]) ? convertHexAddress(args[2]) : JSON.stringify(args[2]);
            jsCode = `mem.watch(${addrWatch}, ${args.length > 3 ? JSON.stringify(args[3]) : ''})`;
            break;
          case 'unwatch':
            if (args.length < 3) {
              console.error('사용법: mem unwatch <id>');
              return;
            }
            const idWatch = parseInt(args[2]);
            
            jsCode = `mem.unwatch(${idWatch})`;
            break;
          default:
            console.error(`알 수 없는 mem 동작: ${action}`);
            console.error('동작 목록: read, write, view, lock, unlock, list, watch, unwatch, trace, untrace');
            return;
        }
        break;
        
      // 스캔 명령어  
      case 'scan':
        if (args.length === 0) {
          console.error('사용법: scan <action> [args...]');
          console.error('액션: type, value, range, increased, decreased, next');
          return;
        }
        
        const scanAction = args[0];
        const scanArgs = args.slice(1);
        
        switch(scanAction) {
          case 'type':
            if (scanArgs.length === 0) {
              console.error('사용법: scan type <value> [type] [protection]');
              return;
            }
            
            // 값 처리 (숫자나 문자열)
            let scanValue;
            if (!isNaN(Number(scanArgs[0]))) {
              // 숫자 처리
              scanValue = scanArgs[0];
            } else {
              // 문자열 처리
              scanValue = JSON.stringify(scanArgs[0]);
            }
            
            const scanType = scanArgs.length > 1 ? JSON.stringify(scanArgs[1]) : '';
            const scanProt = scanArgs.length > 2 ? JSON.stringify(scanArgs[2]) : '';
            
            jsCode = `scan.type(${scanValue}, ${scanType}, ${scanProt})`;
            break;
          case 'value':
            if (scanArgs.length === 0) {
              console.error('사용법: scan value <value> [type]');
              return;
            }
            // 값 처리 (숫자나 문자열)
            let exactValue;
            if (!isNaN(Number(scanArgs[0]))) {
              exactValue = scanArgs[0];
            } else {
              exactValue = JSON.stringify(scanArgs[0]);
            }
            
            jsCode = `scan.value(${exactValue}, ${scanArgs.length > 1 ? JSON.stringify(scanArgs[1]) : ''})`;
            break;
          case 'range':
            if (scanArgs.length < 2) {
              console.error('사용법: scan range <min> <max> [type]');
              return;
            }
            jsCode = `scan.range(${scanArgs[0]}, ${scanArgs[1]}, ${scanArgs.length > 2 ? JSON.stringify(scanArgs[2]) : ''})`;
            break;
          case 'increased':
            jsCode = `scan.increased(${scanArgs.length > 0 ? JSON.stringify(scanArgs[0]) : ''})`;
            break;
          case 'decreased':
            jsCode = `scan.decreased(${scanArgs.length > 0 ? JSON.stringify(scanArgs[0]) : ''})`;
            break;
          case 'next':
            if (scanArgs.length === 0) {
              console.error('사용법: scan next <condition> [type]');
              return;
            }
            console.error('scan next 명령은 아직 CLI에서 지원되지 않습니다. scan.next() 함수를 직접 사용하세요.');
            return;
          default:
            console.error(`알 수 없는 스캔 액션: ${scanAction}`);
            return;
        }
        break;
        
      // 후킹 명령어
      case 'hook':
        if (args.length === 0) {
          console.error('사용법: hook <action> [args...]');
          console.error('액션: method, native, list, unhook');
          return;
        }
        
        const hookAction = args[0];
        const hookArgs = args.slice(1);
        
        switch(hookAction) {
          case 'method':
            if (hookArgs.length === 0) {
              console.error('사용법: hook method <class.method>');
              return;
            }
            jsCode = `hook.method(${JSON.stringify(hookArgs[0])})`;
            break;
          case 'native':
            if (hookArgs.length === 0) {
              console.error('사용법: hook native <function>');
              return;
            }
            // 16진수 주소 처리
            const hookNativeArg = isHexAddress(hookArgs[0]) ? convertHexAddress(hookArgs[0]) : JSON.stringify(hookArgs[0]);
            jsCode = `hook.native(${hookNativeArg})`;
            break;
          case 'list':
            jsCode = `hook.list()`;
            break;
          case 'unhook':
            if (hookArgs.length === 0) {
              console.error('사용법: hook unhook <index>');
              return;
            }
            jsCode = `hook.unhook(${JSON.stringify(hookArgs[0])})`;
            break;
          default:
            console.error(`알 수 없는 후킹 액션: ${hookAction}`);
            return;
        }
        break;
        
      // 함수 호출 명령어
      case 'call':
        if (args.length === 0) {
          console.error('사용법: call <action> [args...]');
          console.error('액션: native, method');
          return;
        }
        
        const callAction = args[0];
        const callArgs = args.slice(1);
        
        switch(callAction) {
          case 'native':
            if (callArgs.length === 0) {
              console.error('사용법: call native <function> [args...]');
              return;
            }
            // 16진수 주소 처리
            const callNativeArg = isHexAddress(callArgs[0]) ? convertHexAddress(callArgs[0]) : JSON.stringify(callArgs[0]);
            jsCode = `call.native(${callNativeArg}, ${callArgs.slice(1).map(arg => {
              // 숫자나 16진수 주소는 따옴표 없이
              if (!isNaN(Number(arg)) || isHexAddress(arg)) {
                return isHexAddress(arg) ? convertHexAddress(arg) : arg;
              }
              return JSON.stringify(arg);
            }).join(', ')})`;
            break;
          case 'method':
            if (callArgs.length < 2) {
              console.error('사용법: call method <class.method> <overloadIndex> [args...]');
              return;
            }
            jsCode = `call.method(${JSON.stringify(callArgs[0])}, ${callArgs[1]}, ${callArgs.slice(2).map(arg => {
              // 숫자는 따옴표 없이
              if (!isNaN(Number(arg))) {
                return arg;
              }
              return JSON.stringify(arg);
            }).join(', ')})`;
            break;
          default:
            console.error(`알 수 없는 호출 액션: ${callAction}`);
            return;
        }
        break;
        
      // 히스토리 명령어
      case 'hist':
        if (args.length === 0) {
          console.error('사용법: hist <action> [args...]');
          console.error('액션: save, list, load, clear, compare');
          return;
        }
        
        const histAction = args[0];
        const histArgs = args.slice(1);
        
        switch(histAction) {
          case 'save':
            jsCode = `hist.save(${histArgs.length > 0 ? JSON.stringify(histArgs[0]) : ''})`;
            break;
          case 'list':
            jsCode = `hist.list()`;
            break;
          case 'load':
            if (histArgs.length === 0) {
              console.error('사용법: hist load <index>');
              return;
            }
            jsCode = `hist.load(${histArgs[0]})`;
            break;
          case 'clear':
            jsCode = `hist.clear()`;
            break;
          case 'compare':
            if (histArgs.length < 2) {
              console.error('사용법: hist compare <index1> <index2>');
              return;
            }
            jsCode = `hist.compare(${histArgs[0]}, ${histArgs[1]})`;
            break;
          default:
            console.error(`알 수 없는 히스토리 액션: ${histAction}`);
            return;
        }
        break;
        
      // 라이브러리 명령어
      case 'lib':
        if (args.length === 0) {
          console.error('사용법: lib <action> [args...]');
          console.error('액션: list, save, clear, remove, move, sort, find, export, duplicate');
          return;
        }
        
        const libAction = args[0];
        const libArgs = args.slice(1);
        
        switch(libAction) {
          case 'list':
            jsCode = `lib.list(${libArgs.length > 0 ? libArgs[0] : ''})`;
            break;
          case 'save':
            if (libArgs.length === 0) {
              console.error('사용법: lib save <index> [label]');
              return;
            }
            jsCode = `sav(${libArgs[0]}, ${libArgs.length > 1 ? JSON.stringify(libArgs[1]) : ''})`;
            break;
          case 'clear':
            jsCode = `lib.clear()`;
            break;
          case 'remove':
            if (libArgs.length === 0) {
              console.error('사용법: lib remove <index>');
              return;
            }
            jsCode = `lib.remove(${libArgs[0]})`;
            break;
          case 'move':
            if (libArgs.length < 2) {
              console.error('사용법: lib move <fromIndex> <toIndex>');
              return;
            }
            jsCode = `lib.move(${libArgs[0]}, ${libArgs[1]})`;
            break;
          case 'sort':
            jsCode = `lib.sort(${libArgs.length > 0 ? JSON.stringify(libArgs[0]) : ''})`;
            break;
          case 'find':
            if (libArgs.length === 0) {
              console.error('사용법: lib find <pattern> [field]');
              return;
            }
            jsCode = `lib.find(${JSON.stringify(libArgs[0])}, ${libArgs.length > 1 ? JSON.stringify(libArgs[1]) : ''})`;
            break;
          case 'export':
            if (libArgs.length === 0) {
              console.error('사용법: lib export <index>');
              return;
            }
            jsCode = `lib.export(${libArgs[0]})`;
            break;
          case 'duplicate':
            if (libArgs.length === 0) {
              console.error('사용법: lib duplicate <index>');
              return;
            }
            jsCode = `lib.duplicate(${libArgs[0]})`;
            break;
          default:
            console.error(`알 수 없는 라이브러리 액션: ${libAction}`);
            return;
        }
        break;
        
      // 명령어 관리
      case 'cmd':
        if (args.length === 0) {
          console.error('사용법: cmd <action> [args...]');
          console.error('액션: history, alias');
          return;
        }
        
        const cmdAction = args[0];
        const cmdArgs = args.slice(1);
        
        switch(cmdAction) {
          case 'history':
            jsCode = `cmd.history()`;
            break;
          case 'alias':
            if (cmdArgs.length < 2) {
              console.error('사용법: cmd alias <name> <command>');
              return;
            }
            jsCode = `cmd.alias(${JSON.stringify(cmdArgs[0])}, ${JSON.stringify(cmdArgs.slice(1).join(' '))})`;
            break;
          default:
            console.error(`알 수 없는 명령어 액션: ${cmdAction}`);
            return;
        }
        break;
        
      // 내비게이션 명령어
      case 'nxt':
        jsCode = `nxt(${args.length > 0 ? args[0] : ''})`;
        break;
      case 'prv':
        jsCode = `prv(${args.length > 0 ? args[0] : ''})`;
        break;
      case 'grep':
        if (args.length === 0) {
          console.error('사용법: grep <pattern>');
          return;
        }
        jsCode = `grep(${JSON.stringify(args[0])})`;
        break;
      case 'sort':
        jsCode = `sort(${args.length > 0 ? JSON.stringify(args[0]) : ''})`;
        break;
        
      // 알 수 없는 명령어
      default:
        console.error(`알 수 없는 명령어: ${cmd}`);
        console.error('도움말을 보려면 help를 입력하세요.');
        return;
    }
    
    if (jsCode) {
      await script.exports.executeCommand(jsCode);
    }
  } catch (e) {
    console.error(`명령어 실행 오류: ${e.message}`);
    throw e;
  }
}

/**
 * 도움말 표시
 */
function showHelp() {
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
  console.log('');
  console.log('참고: "값" 처럼 공백이 포함된 인자는 따옴표로 묶어서 사용하세요.');
  console.log('      0x로 시작하는 16진수 주소값은 직접 입력할 수 있습니다. (예: 0x7ff8ad83b0)');
}

module.exports = {
  createEvaluator
}; 