/**
 * gdbg.js - 메인 진입점
 * frida-compile 호환 모듈
 */

const config = require('./config');
const utils = require('./utils');
const log = require('./logger');
const memory = require('./memory');
const list = require('./list');
const hook = require('./hook');
const scan = require('./scan');
const mem = require('./mem');
const hist = require('./history');
const lib = require('./library');
const call = require('./call');
const cmd = require('./cmd');

// 전역 상태 초기화
require('./state');

// 전역 별칭 및 함수 내보내기
global.help = require('./help');
global.nxt = require('./navigation').nxt;
global.prv = require('./navigation').prv;
global.sav = require('./navigation').sav;
global.sort = require('./navigation').sort;
global.grep = require('./navigation').grep;
global.config = config;

// 기능 별 모듈 내보내기
global.list = list;
global.hook = hook;
global.call = call;
global.scan = scan;
global.mem = mem;
global.hist = hist;
global.lib = lib;
global.cmd = cmd;

// 전역 별칭 등록
global.clss = global.list.class.bind(global.list);
global.meths = global.list.method.bind(global.list);
global.modls = global.list.module.bind(global.list);
global.exps = global.list.export.bind(global.list);
global.hookm = global.hook.method.bind(global.hook);
global.hookn = global.hook.native.bind(global.hook);
global.unhook = global.hook.unhook.bind(global.hook);
global.hooked = global.hook.list.bind(global.hook);
global.calln = global.call.native.bind(global.call);
global.callm = global.call.method.bind(global.call);
global.srch = global.scan.type.bind(global.scan);
global.exct = global.scan.value.bind(global.scan);
global.ls = global.lib.list.bind(global.lib);
global.mv = global.lib.move.bind(global.lib);
global.rm = global.lib.remove.bind(global.lib);
global.r = global.mem.read.bind(global.mem);
global.w = global.mem.write.bind(global.mem);
global.l = global.mem.lock.bind(global.mem);
global.ul = global.mem.unlock.bind(global.mem);
global.v = global.mem.view.bind(global.mem);

// CLI 지원을 위한 RPC 핸들러 설정
(function setupRpcHandler() {
  // 외부에서 호출할 수 있는 핸들러
  rpc.exports = {
    // 명령어 실행
    executeCommand: function(cmd) {
      try {
        // 명령어 실행
        const result = eval(cmd);
        return {
          status: 'success',
          result: result
        };
      } catch (e) {
        return {
          status: 'error',
          error: e.toString()
        };
      }
    }
  };
})();

// 초기 정보 메시지
console.log(`
        _____ _____  ____   _____ 
       / ____|  __ \\|  _ \\ / ____|
      | |  __| |  | | |_) | |  __ 
      | | |_ | |  | |  _ <| | |_ |
      | |__| | |__| | |_) | |__| |
       \\_____|_____/|____/ \\_____|
`);
console.log(`
===========================================
    Game Debugger & Memory Tool v${config.version}
          Created by @MswTester
===========================================
`);

log.info('gdbg.js loaded. Type help() to see available commands.');

// 환경 감지
(function detectEnvironment() {
  try {
    if (ObjC.available) {
      log.info('iOS environment detected');
    } else if (Java.available) {
      log.info('Android environment detected');
    }
  } catch (_) {
    // No specific environment detected
  }
})();

// 명령어 프록시 설정
(function setupCommandProxy() {
  const originalEval = global.eval;
  global.eval = function(cmd) {
    if (typeof cmd === 'string' && cmd.trim() && 
        !cmd.startsWith('(') && !cmd.startsWith('function')) {
      global.state.commands.push(cmd);
      if (global.state.commands.length > 100) global.state.commands.shift();
    }
    return originalEval.call(this, cmd);
  };
})(); 