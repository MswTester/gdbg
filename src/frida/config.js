/**
 * 설정 모듈
 */

// 설정 및 상태 관리
const CONFIG = {
    version: "0.3.1",
    pageSize: 20,        // 페이지당 표시할 항목 수
    scanInterval: 200,   // 메모리 스캔 간격 (ms)
    defaultScanType: 'uint',
    colors: {
        enabled: true,   // 색상 로깅 활성화
        info: '\x1b[36m',    // 청록색
        success: '\x1b[32m',  // 녹색
        error: '\x1b[31m',    // 빨간색
        warning: '\x1b[33m',  // 노란색
        reset: '\x1b[0m'      // 색상 초기화
    }
};

// 설정 관련 명령어
const configCommands = {
    show() {
        const log = require('./logger');
        log.info('현재 설정:');
        console.log(`  페이지 크기: ${CONFIG.pageSize}`);
        console.log(`  색상 출력: ${CONFIG.colors.enabled ? '활성화' : '비활성화'}`);
        console.log(`  기본 스캔 타입: ${CONFIG.defaultScanType}`);
    },
    
    set(key, value) {
        const log = require('./logger');
        if (key === 'pageSize') {
            if (typeof value !== 'number' || value < 1) {
                return log.error('pageSize는 양수여야 합니다');
            }
            CONFIG.pageSize = value;
            log.success(`페이지 크기를 ${value}로 설정했습니다`);
        } else if (key === 'colors') {
            CONFIG.colors.enabled = !!value;
            log.success(`색상 출력을 ${value ? '활성화' : '비활성화'}했습니다`);
        } else if (key === 'defaultScanType') {
            if (!['byte', 'short', 'int', 'uint', 'float', 'string'].includes(value)) {
                return log.error('올바르지 않은 스캔 타입입니다');
            }
            CONFIG.defaultScanType = value;
            log.success(`기본 스캔 타입을 ${value}로 설정했습니다`);
        } else {
            log.error(`알 수 없는 설정: ${key}`);
        }
    }
};

module.exports = Object.assign({}, CONFIG, configCommands); 