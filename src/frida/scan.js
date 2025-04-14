/**
 * Memory scanning module
 */

const utils = require('./utils');
const log = require('./logger');
const config = require('./config');

const scan = {
    /**
     * 메모리에서 지정된 유형과 값으로 스캔
     * @param {any} val 검색할 값
     * @param {string} t 검색할 데이터 유형
     * @param {string} p 메모리 보호 유형
     */
    type(val, t = config.defaultScanType, p = 'r-x') {
        global.state.logs.length = 0;
        global.state.lastScanType = t;
        let idx = 0, count = 0;
        try {
            // 값 유형 검사 및 로깅
            const valueType = typeof val;
            log.info(`Scanning memory (type: ${t}, value: ${val} [${valueType}], prot: ${p})...`);
            
            // 패턴 생성
            const pattern = utils.toPattern(t, val);
            if (!pattern) {
                log.error(`Failed to create search pattern for value '${val}' with type '${t}'`);
                return;
            }
            
            // 메모리 스캔 수행
            Process.enumerateRanges({ protection: p }).forEach(r => {
                try {
                    Memory.scanSync(r.base, r.size, pattern).forEach(res => {
                        global.state.logs.push({
                            index: idx++,
                            label: `${utils.formatAddress(res.address)} (${t})`,
                            value: { address: res.address, type: t },
                            type: 'ptr'
                        });
                        count++;
                    });
                } catch (e) {
                    log.warning(`Error scanning range ${utils.formatAddress(r.base)}: ${e.message}`);
                }
            });
            
            log.success(`Scan complete: found ${count} results`);
            global.nxt(0);
        } catch (e) {
            log.error(`scan.type(): ${e}`);
        }
    },

    /**
     * 이전 스캔 결과에서 조건에 맞는 값 필터링
     * @param {Function} cond 필터링 조건 함수
     * @param {string} t 데이터 유형
     */
    next(cond, t = global.state.lastScanType) {
        if (!global.state.logs.length) return log.error('scan.next(): No previous scan results');
        
        const snapshot = global.state.logs.map(x => x.value.address);
        global.state.logs.length = 0;
        let idx = 0, count = 0;
        
        log.info(`Filtering ${snapshot.length} addresses with condition...`);
        
        const memory = require('./memory');
        snapshot.forEach(ptr => {
            try {
                const val = memory.reader[t](ptr);
                if (cond(val)) {
                    global.state.logs.push({
                        index: idx++,
                        label: `${utils.formatAddress(ptr)} (${t}) = ${val}`,
                        value: { address: ptr, type: t },
                        type: 'ptr'
                    });
                    count++;
                }
            } catch (_) {}
        });
        
        global.state.lastScanType = t;
        log.success(`Filter complete: found ${count} results`);
        global.nxt(0);
    },
    
    /**
     * 정확한 값 검색
     * @param {any} val 검색할 값
     * @param {string} t 데이터 유형
     */
    value(val, t = global.state.lastScanType) {
        // 문자열이 숫자로 변환 가능한지 확인
        if (typeof val === 'string' && !isNaN(Number(val))) {
            val = Number(val);
        }
        
        this.next(v => v === val, t);
    },
    
    /**
     * 범위 내 값 검색
     * @param {number} min 최소값
     * @param {number} max 최대값
     * @param {string} t 데이터 유형
     */
    range(min, max, t = global.state.lastScanType) {
        // 문자열이 숫자로 변환 가능한지 확인
        if (typeof min === 'string' && !isNaN(Number(min))) {
            min = Number(min);
        }
        if (typeof max === 'string' && !isNaN(Number(max))) {
            max = Number(max);
        }
        
        this.next(v => v >= min && v <= max, t);
    },
    
    /**
     * 증가된 값 검색
     * @param {string} t 데이터 유형
     */
    increased(t = global.state.lastScanType) {
        if (!global.state.logs.some(l => l.hasOwnProperty('prevValue'))) {
            // First snapshot
            const memory = require('./memory');
            global.state.logs.forEach((l, i) => {
                try {
                    l.prevValue = memory.reader[t](l.value.address);
                } catch (_) {}
            });
            
            log.info('Snapshot saved for increased value search. Run scan.increased() again to find values that increased.');
            return;
        }
        
        this.next(function(v) {
            const idx = global.state.logs.findIndex(l => 
                l.value.address.equals(this.address) && l.hasOwnProperty('prevValue'));
            return idx >= 0 && v > global.state.logs[idx].prevValue;
        }, t);
    },
    
    /**
     * 감소된 값 검색
     * @param {string} t 데이터 유형
     */
    decreased(t = global.state.lastScanType) {
        if (!global.state.logs.some(l => l.hasOwnProperty('prevValue'))) {
            const memory = require('./memory');
            global.state.logs.forEach((l, i) => {
                try {
                    l.prevValue = memory.reader[t](l.value.address);
                } catch (_) {}
            });
            
            log.info('Snapshot saved for decreased value search. Run scan.decreased() again to find values that decreased.');
            return;
        }
        
        this.next(function(v) {
            const idx = global.state.logs.findIndex(l => 
                l.value.address.equals(this.address) && l.hasOwnProperty('prevValue'));
            return idx >= 0 && v < global.state.logs[idx].prevValue;
        }, t);
    }
};

module.exports = scan; 