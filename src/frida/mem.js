/**
 * Memory manipulation module
 */

const utils = require('./utils');
const log = require('./logger');
const config = require('./config');

const locks = {};
const lockIndex = [];
const traces = {};
const traceIndex = [];
const watches = {};
const watchIndex = [];

let lockCounter = 0;
let traceCounter = 0;
let watchCounter = 0;

const mem = {
    read(i, t = "uint") {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.read(): Invalid pointer @ ${i}`);
        const addr = v.address || v, type = t || v.type;
        
        try {
            const memory = require('./memory');
            const val = memory.reader[type](addr);
            log.info(`메모리 읽기: [${utils.formatAddress(addr)}] (${type}) = ${val}`);
            return val;
        } catch (e) {
            log.error(`mem.read() 오류: ${e}`);
        }
    },

    write(i, val, t) {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.write(): Invalid pointer @ ${i}`);
        const addr = v.address || v, type = t || v.type;
        
        try {
            const memory = require('./memory');
            const oldVal = memory.reader[type](addr);
            memory.writer[type](addr, val);
            log.success(`메모리 쓰기 완료: ${utils.formatAddress(addr)} (${type}) [${oldVal} → ${val}]`);
        } catch (e) {
            log.error(`mem.write() 오류: ${e}`);
        }
    },

    view(i, t = "byte", lines = 10) {
        const v = utils.resolve(i, 'ptr');
        if (!v) return log.error(`mem.view(): Invalid pointer @ ${i}`);
        const baseAddr = v.address || v;
        const absLines = Math.abs(lines);
        
        try {
            // Determine line offset based on lines parameter
            const startOffset = lines < 0 ? -16 * absLines : 0;
            const totalLines = lines < 0 ? absLines * 2 : absLines;
            
            log.info(`메모리 주소 ${utils.formatAddress(baseAddr.add(startOffset))} 에서 ${totalLines}줄 보기 (타입: ${t})`);
            
            // Print header
            console.log('                      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F');
            
            for (let lineIdx = 0; lineIdx < totalLines; lineIdx++) {
                const lineOffset = startOffset + (lineIdx * 16);
                const currentAddr = baseAddr.add(lineOffset);
                let hexValues = '';
                let typeValues = '';
                
                try {
                    // Get bytes for the current line
                    const bytes = currentAddr.readByteArray(16);
                    const bytesArray = Array.from(new Uint8Array(bytes));
                    
                    // Format bytes as hex
                    hexValues = bytesArray.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
                    
                    // Format type-specific values
                    if (t === 'byte') {
                        // Just use hex values
                        typeValues = '';
                    } else if (t === 'int' || t === 'uint') {
                        // Show 4 32-bit integers per line (every 4 bytes)
                        typeValues = '  ';
                        for (let j = 0; j < 16; j += 4) {
                            if (j + 3 < 16) {
                                try {
                                    const intValue = t === 'int' 
                                        ? currentAddr.add(j).readS32() 
                                        : currentAddr.add(j).readU32();
                                    typeValues += intValue.toString().padStart(10, ' ') + '  ';
                                } catch (e) {
                                    typeValues += '          ';
                                }
                            }
                        }
                    } else if (t === 'short') {
                        // Show 8 16-bit values per line (every 2 bytes)
                        typeValues = '  ';
                        for (let j = 0; j < 16; j += 2) {
                            if (j + 1 < 16) {
                                try {
                                    const shortValue = currentAddr.add(j).readS16();
                                    typeValues += shortValue.toString().padStart(6, ' ') + '  ';
                                } catch (e) {
                                    typeValues += '      ';
                                }
                            }
                        }
                    } else if (t === 'float') {
                        // Show 4 floats per line (every 4 bytes)
                        typeValues = '  ';
                        for (let j = 0; j < 16; j += 4) {
                            if (j + 3 < 16) {
                                try {
                                    const floatValue = currentAddr.add(j).readFloat().toFixed(2);
                                    typeValues += floatValue.padStart(8, ' ') + '  ';
                                } catch (e) {
                                    typeValues += '        ';
                                }
                            }
                        }
                    }
                } catch (e) {
                    hexValues = 'Cannot read memory';
                }
                
                // Print the line
                console.log(`[${lineIdx}] ${utils.formatAddress(currentAddr).padEnd(16, ' ')}  ${hexValues}${typeValues}`);
            }
            
            return baseAddr;
        } catch (e) {
            log.error(`mem.view() 오류: ${e}`);
        }
    },

    /**
     * 메모리 주소를 잠가서 지정한 값으로 유지합니다.
     * @param {string|number} address 16진수 문자열 또는 숫자 주소
     * @param {any} value 유지할 값
     * @param {string} type 데이터 타입 (기본값: 'int')
     */
    lock(address, value, type = 'int') {
        const parsedAddr = typeof address === 'string' ? 
            ptr(address) : 
            ptr(address.toString());
        
        const id = lockCounter++;
        lockIndex.push(id);
        
        // 초기 값 쓰기
        this.write(parsedAddr, value, type);
        
        // 인터벌 설정
        const intervalId = setInterval(() => {
            try {
                this.write(parsedAddr, value, type);
            } catch (e) {
                console.error(`Lock ${id} 오류: ${e.message}`);
                this.unlock(id);
            }
        }, 100);
        
        locks[id] = {
            id,
            address: parsedAddr,
            value,
            type,
            intervalId,
            createdAt: new Date()
        };
        
        console.log(`메모리 잠금 설정됨 #${id}: ${parsedAddr} = ${value} (${type})`);
        return id;
    },
    
    /**
     * 메모리 잠금을 해제합니다.
     * @param {number} id 잠금 ID
     */
    unlock(id) {
        if (!locks[id]) {
            console.error(`ID ${id}에 대한 잠금을 찾을 수 없습니다.`);
            return false;
        }
        
        clearInterval(locks[id].intervalId);
        
        const idx = lockIndex.indexOf(id);
        if (idx !== -1) {
            lockIndex.splice(idx, 1);
        }
        
        const lock = locks[id];
        delete locks[id];
        
        console.log(`메모리 잠금 해제됨 #${id}: ${lock.address}`);
        return true;
    },

    /**
     * 모든 잠금 목록을 표시합니다.
     */
    list() {
        console.log('\n----- 메모리 감시 목록 -----');
        
        // 잠금 목록 표시
        if (lockIndex.length > 0) {
            console.log('\n[잠금 목록]');
            for (const id of lockIndex) {
                const lock = locks[id];
                console.log(`#${id}: ${lock.address} = ${lock.value} (${lock.type}) - ${formatTime(lock.createdAt)}`);
            }
        }
        
        // 추적 목록 표시
        if (traceIndex.length > 0) {
            console.log('\n[추적 목록]');
            for (const id of traceIndex) {
                const trace = traces[id];
                console.log(`#${id}: ${trace.address} (${trace.type}) - ${formatTime(trace.createdAt)}`);
            }
        }
        
        // 감시 목록 표시
        if (watchIndex.length > 0) {
            console.log('\n[감시 목록]');
            for (const id of watchIndex) {
                const watch = watches[id];
                console.log(`#${id}: ${watch.address} (${watch.type}) - ${formatTime(watch.createdAt)}`);
            }
        }
        
        if (lockIndex.length === 0 && traceIndex.length === 0 && watchIndex.length === 0) {
            console.log('활성화된 메모리 감시가 없습니다.');
        }
        
        console.log('\n-------------------------');
    },
    
    /**
     * 이전 버전과의 호환성을 위한 alias
     */
    locked() {
        return this.list();
    },

    /**
     * 메모리 주소를 추적합니다.
     * @param {string|number} address 16진수 문자열 또는 숫자 주소
     * @param {string} type 데이터 타입 (기본값: 'int')
     */
    trace(address, type = 'int') {
        const parsedAddr = typeof address === 'string' ? 
            ptr(address) : 
            ptr(address.toString());
        
        const id = traceCounter++;
        traceIndex.push(id);
        
        // 초기 값 읽기
        let prevValue;
        try {
            prevValue = this.read(parsedAddr, type);
        } catch (e) {
            console.error(`초기 값 읽기 오류: ${e.message}`);
            prevValue = null;
        }
        
        // 인터벌 설정
        const intervalId = setInterval(() => {
            try {
                const currentValue = this.read(parsedAddr, type);
                if (JSON.stringify(currentValue) !== JSON.stringify(prevValue)) {
                    console.log(`[Trace #${id}] ${parsedAddr} 변경됨: ${prevValue} → ${currentValue}`);
                    prevValue = currentValue;
                }
            } catch (e) {
                console.error(`Trace ${id} 오류: ${e.message}`);
                this.untrace(id);
            }
        }, 100);
        
        traces[id] = {
            id,
            address: parsedAddr,
            type,
            intervalId,
            createdAt: new Date()
        };
        
        console.log(`메모리 추적 설정됨 #${id}: ${parsedAddr} (${type})`);
        return id;
    },
    
    /**
     * 메모리 추적을 중지합니다.
     * @param {number} id 추적 ID
     */
    untrace(id) {
        if (!traces[id]) {
            console.error(`ID ${id}에 대한 추적을 찾을 수 없습니다.`);
            return false;
        }
        
        clearInterval(traces[id].intervalId);
        
        const idx = traceIndex.indexOf(id);
        if (idx !== -1) {
            traceIndex.splice(idx, 1);
        }
        
        const trace = traces[id];
        delete traces[id];
        
        console.log(`메모리 추적 중지됨 #${id}: ${trace.address}`);
        return true;
    },
    
    /**
     * 메모리 주소의 값 변경을 감시합니다.
     * @param {string|number} address 16진수 문자열 또는 숫자 주소
     * @param {string} type 데이터 타입 (기본값: 'int')
     */
    watch(address, type = 'int') {
        const parsedAddr = typeof address === 'string' ? 
            ptr(address) : 
            ptr(address.toString());
        
        const id = watchCounter++;
        watchIndex.push(id);
        
        // 초기 값 읽기
        let prevValue;
        try {
            prevValue = this.read(parsedAddr, type);
        } catch (e) {
            console.error(`초기 값 읽기 오류: ${e.message}`);
            prevValue = null;
        }
        
        // 변경 기록
        const changes = [];
        
        // 인터벌 설정
        const intervalId = setInterval(() => {
            try {
                const currentValue = this.read(parsedAddr, type);
                if (JSON.stringify(currentValue) !== JSON.stringify(prevValue)) {
                    const timestamp = new Date();
                    const change = {
                        timestamp,
                        from: prevValue,
                        to: currentValue
                    };
                    changes.push(change);
                    console.log(`[Watch #${id}] ${parsedAddr} 변경됨: ${prevValue} → ${currentValue} (${formatTime(timestamp)})`);
                    prevValue = currentValue;
                }
            } catch (e) {
                console.error(`Watch ${id} 오류: ${e.message}`);
                this.unwatch(id);
            }
        }, 100);
        
        watches[id] = {
            id,
            address: parsedAddr,
            type,
            intervalId,
            changes,
            createdAt: new Date()
        };
        
        console.log(`메모리 감시 설정됨 #${id}: ${parsedAddr} (${type})`);
        return id;
    },
    
    /**
     * 메모리 감시를 중지하고 변경 요약을 표시합니다.
     * @param {number} id 감시 ID
     */
    unwatch(id) {
        if (!watches[id]) {
            console.error(`ID ${id}에 대한 감시를 찾을 수 없습니다.`);
            return false;
        }
        
        clearInterval(watches[id].intervalId);
        
        const idx = watchIndex.indexOf(id);
        if (idx !== -1) {
            watchIndex.splice(idx, 1);
        }
        
        const watch = watches[id];
        
        console.log(`\n----- 메모리 감시 요약 #${id} -----`);
        console.log(`주소: ${watch.address} (${watch.type})`);
        console.log(`감시 시작: ${formatTime(watch.createdAt)}`);
        console.log(`감시 종료: ${formatTime(new Date())}`);
        console.log(`변경 횟수: ${watch.changes.length}`);
        
        if (watch.changes.length > 0) {
            console.log('\n변경 기록:');
            watch.changes.forEach((change, index) => {
                console.log(`${index + 1}. ${formatTime(change.timestamp)}: ${change.from} → ${change.to}`);
            });
        } else {
            console.log('\n감시 기간 동안 값 변경이 없었습니다.');
        }
        
        console.log('\n-------------------------');
        
        delete watches[id];
        
        return true;
    },
};

/**
 * 날짜를 포맷팅합니다.
 * @param {Date} date 날짜 객체
 * @returns {string} 포맷팅된 날짜 문자열
 */
function formatTime(date) {
    return date.toLocaleTimeString('ko-KR', { 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit',
        hour12: false 
    });
}

module.exports = mem; 