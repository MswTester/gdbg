/**
 * 로깅 시스템 모듈
 */

const config = require('./config');

// 로깅 시스템
const log = {
    format(type, msg) {
        const c = config.colors;
        if (!c.enabled) return msg;
        
        switch (type) {
            case 'info': return `${c.info}${msg}${c.reset}`;
            case 'success': return `${c.success}${msg}${c.reset}`;
            case 'error': return `${c.error}${msg}${c.reset}`;
            case 'warning': return `${c.warning}${msg}${c.reset}`;
            default: return msg;
        }
    },

    info(msg) {
        console.log(this.format('info', `[i] ${msg}`));
    },

    success(msg) {
        console.log(this.format('success', `[+] ${msg}`));
    },

    error(msg) {
        console.log(this.format('error', `[!] ${msg}`));
    },

    warning(msg) {
        console.log(this.format('warning', `[*] ${msg}`));
    },

    table(items, formatter) {
        if (!items || !items.length) {
            this.info('표시할 데이터가 없습니다');
            return;
        }

        // 모든 환경을 위한 간소화된 출력
        items.forEach((item, idx) => console.log(formatter(item, idx)));
    }
};

module.exports = log; 