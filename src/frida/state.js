/**
 * 전역 상태 관리 모듈
 */

const config = require('./config');

// 글로벌 상태 초기화
global.state = {
    logs: [],            // 메인 로그 저장
    lib: [],             // 라이브러리 저장
    hist: [],            // 히스토리 저장
    locks: [],           // 메모리 잠금 저장
    hooks: [],           // 후크 저장
    logIndex: 0,         // 현재 로그 인덱스
    lastScanType: config.defaultScanType,
    commands: []         // 명령어 히스토리
}; 