/**
 * Frida 관련 명령어 모듈
 */

const frida = require('frida');
const path = require('path');
const fs = require('fs');
const replModule = require('../repl');

/**
 * Frida 관련 명령어 등록
 * @param {import('commander').Command} program Commander 프로그램 인스턴스
 */
function register(program) {
  program
    .option('-D, --device <ID>', 'Connect to device with the given ID')
    .option('-U, --usb', 'Connect to USB device')
    .option('-R, --remote', 'Connect to remote frida-server')
    .option('-H, --host <HOST>', 'Connect to remote frida-server on HOST')
    .option('-f, --file <TARGET>', 'Spawn FILE')
    .option('-n, --attach-name <NAME>', 'Attach to NAME')
    .option('-p, --pid <PID>', 'Attach to process with PID')
    .description('Connect to a target process using Frida and start a REPL session')
    .action(async (options) => {
      // 옵션 검증
      if (!options.device && !options.usb && !options.remote && !options.host) {
        console.error('오류: 장치 옵션이 제공되지 않았습니다.');
        program.outputHelp();
        process.exit(1);
      }
      if (!options.file && !options.attachName && !options.pid) {
        console.error('오류: 타겟이 지정되지 않았습니다.');
        program.outputHelp();
        process.exit(1);
      }

      // Frida를 사용하여 대상 프로세스에 연결
      let session, script;
      try {
        const device = await getDevice(options);
        
        if(options.file) {
          const pid = await device.spawn(options.file);
          session = await device.attach(pid);
        } else {
          session = await device.attach(options.attachName || +options.pid);
        }
        console.log('대상 프로세스에 연결되었습니다.');
        
        // gdbg 스크립트 로드
        const gdbgScript = loadGdbgScript();
        script = await session.createScript(gdbgScript);
        await script.load();
        await session.resume();
        
        // 스크립트 메시지 처리
        script.message.connect((message, data) => {
          if (message.type === 'send') {
            console.log(message.payload);
          } else if (message.type === 'error') {
            console.error('스크립트 오류:', message.stack);
          }
        });
        
        console.log('gdbg 스크립트가 성공적으로 로드되었습니다.');
      } catch (error) {
        console.error('대상 프로세스 연결 오류:', error.message);
        process.exit(1);
      }

      // REPL 시작
      replModule.startRepl(session, script);
    });
}

/**
 * 옵션에 따라 Frida 장치 가져오기
 * @param {Object} options 명령 옵션
 * @returns {Promise<any>} Frida 장치 
 */
async function getDevice(options) {
  return (
    options.usb ? frida.getUsbDevice() :
    options.remote ? frida.getRemoteDevice() :
    options.host ? frida.getDeviceManager().addRemoteDevice(options.host) :
    options.device ? frida.getDevice(options.device) :
    frida.getLocalDevice()
  );
}

/**
 * gdbg.js 스크립트 로드
 * @returns {string} 스크립트 내용
 */
function loadGdbgScript() {
  try {
    const gdbgPath = path.join(__dirname, '../../gdbg.js');
    return fs.readFileSync(gdbgPath, 'utf8');
  } catch (error) {
    console.error('gdbg.js 스크립트를 로드할 수 없습니다:', error.message);
    console.error('frida-compile을 사용하여 스크립트를 컴파일하세요:');
    console.error('  npm run compile-agent');
    process.exit(1);
  }
}

module.exports = {
  register
}; 