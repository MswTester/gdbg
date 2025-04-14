/**
 * 탐색 관련 기능 모듈
 */

const config = require('./config');
const utils = require('./utils');
const log = require('./logger');

function nxt(o = config.pageSize, s = config.pageSize) {
    global.state.logIndex += o;
    if (global.state.logIndex < 0) global.state.logIndex = 0;
    if (global.state.logIndex >= global.state.logs.length) global.state.logIndex = Math.max(0, global.state.logs.length - s);
    
    log.info(`항목 ${global.state.logIndex + 1}-${Math.min(global.state.logIndex + s, global.state.logs.length)} / ${global.state.logs.length}`);
    
    const items = global.state.logs.slice(global.state.logIndex, Math.min(global.state.logIndex + s, global.state.logs.length));
    
    if (!items.length) {
        log.info('표시할 항목이 없습니다');
        return;
    }
    
    items.forEach(l => console.log(`[${l.index}] ${l.label}`));
}

function prv(s = config.pageSize) {
    nxt(-s, s);
}

function sav(i, offset) {
    // 오프셋이 제공되면 메모리 뷰에서 저장함을 의미
    if (offset !== undefined) {
        try {
            const v = utils.resolve(i, 'ptr');
            if (!v) return log.error(`sav(): 유효하지 않은 포인터 @ ${i}`);
            
            const baseAddr = v.address || v;
            
            // 실제 오프셋 계산
            const lineOffset = Math.floor(offset / 16) * 16;
            const byteOffset = offset % 16;
            const targetAddr = baseAddr.add(lineOffset + byteOffset);
            
            // 특정 주소에 대한 새 로그 항목 생성
            const ptr = {
                index: global.state.lib.length,
                label: `${utils.formatAddress(targetAddr)} (ptr from view offset ${offset})`,
                value: { address: targetAddr, type: 'byte' },
                type: 'ptr'
            };
            
            global.state.lib.push(ptr);
            log.success(`오프셋 ${offset}의 주소를 lib[${global.state.lib.length - 1}]로 저장했습니다`);
            return;
        } catch (e) {
            log.error(`sav(): ${e}`);
            return;
        }
    }
    
    // 로그 항목 저장을 위한 원래 동작
    const l = global.state.logs[i];
    if (!l) return log.error(`sav(): 유효하지 않은 로그 인덱스 ${i}`);
    global.state.lib.push({ ...l });
    log.success(`lib[${global.state.lib.length - 1}]로 저장했습니다`);
}

function sort() {
    if (!global.state.logs.length) return log.error("sort(): 로그 없음");
    const t = global.state.logs[0].type;
    let sorted = [...global.state.logs];

    try {
        if (t === 'class' || t === 'func' || t === 'method') {
            sorted.sort((a, b) => a.label.localeCompare(b.label));
        } else if (t === 'module') {
            sorted.sort((a, b) => a.value.base.toString().localeCompare(b.value.base.toString()));
        } else if (t === 'ptr') {
            sorted.sort((a, b) => a.value.address.toString().localeCompare(b.value.address.toString()));
        } else {
            return log.error(`sort(): 지원되지 않는 타입 "${t}"`);
        }

        global.state.logs.length = 0;
        sorted.forEach((x, i) => {
            x.index = i;
            global.state.logs.push(x);
        });

        log.success(`${t} 기준으로 정렬됨`);
        nxt(0);
    } catch (e) {
        log.error(`sort() 실패: ${e}`);
    }
}

function grep(pattern, options = {}) {
    if (!global.state.logs.length) return log.error('grep: 검색할 로그가 없습니다');
    
    const caseSensitive = options.caseSensitive !== undefined ? options.caseSensitive : false;
    const matchField = options.field || 'label';
    
    try {
        log.info(`grep: "${pattern}" ${caseSensitive ? '대소문자 구분' : '대소문자 구분 안함'} 검색 중...`);
        
        // 정규식 객체 생성
        const regex = new RegExp(pattern, caseSensitive ? '' : 'i');
        
        // 검색 결과 저장
        const searchResults = [];
        
        global.state.logs.forEach(item => {
            const testValue = matchField === 'label' ? item.label : 
                             (matchField === 'type' ? item.type : 
                             (matchField === 'value' ? JSON.stringify(item.value) : item.label));
            
            if (regex.test(testValue)) {
                searchResults.push({...item});
            }
        });
        
        if (searchResults.length === 0) {
            log.info(`grep: 패턴 "${pattern}"에 대한 일치 항목이 없습니다`);
            return;
        }
        
        // 기존 로그 백업 (hist 모듈에 의존)
        if (global.hist && global.hist.save) {
            global.hist.save('Before grep search');
        }
        
        // 검색 결과로 로그 업데이트
        global.state.logs.length = 0;
        searchResults.forEach((item, idx) => {
            global.state.logs.push({
                ...item,
                index: idx
            });
        });
        
        log.success(`grep: ${searchResults.length}개의 일치 항목 발견`);
        nxt(0);
    } catch (e) {
        if (e instanceof SyntaxError) {
            log.error(`grep: 정규식 오류 - ${e.message}`);
        } else {
            log.error(`grep: ${e.message}`);
        }
    }
}

module.exports = {
    nxt,
    prv,
    sav,
    sort,
    grep
}; 