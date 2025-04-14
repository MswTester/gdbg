/**
 * Utilities module
 */

const config = require('./config');
const log = require('./logger');

const utils = {
    /**
     * Format address to hex string
     * @param {NativePointer} address 
     * @returns {string}
     */
    formatAddress(address) {
        if (!address) return 'null';
        return address.toString();
    },

    /**
     * Format size to human readable string
     * @param {number} size 
     * @returns {string}
     */
    formatSize(size) {
        if (size < 1024) return size + ' B';
        if (size < 1024 * 1024) return (size / 1024).toFixed(2) + ' KB';
        if (size < 1024 * 1024 * 1024) return (size / 1024 / 1024).toFixed(2) + ' MB';
        return (size / 1024 / 1024 / 1024).toFixed(2) + ' GB';
    },

    /**
     * Get data type information
     * @param {string} type 
     * @returns {Object} type information
     */
    getTypeInfo(type) {
        const types = {
            'int': { size: 4, read: 'readInt', write: 'writeInt' },
            'int8': { size: 1, read: 'readS8', write: 'writeS8' },
            'int16': { size: 2, read: 'readS16', write: 'writeS16' },
            'int32': { size: 4, read: 'readS32', write: 'writeS32' },
            'int64': { size: 8, read: 'readS64', write: 'writeS64' },
            'uint8': { size: 1, read: 'readU8', write: 'writeU8' },
            'uint16': { size: 2, read: 'readU16', write: 'writeU16' },
            'uint32': { size: 4, read: 'readU32', write: 'writeU32' },
            'uint64': { size: 8, read: 'readU64', write: 'writeU64' },
            'float': { size: 4, read: 'readFloat', write: 'writeFloat' },
            'double': { size: 8, read: 'readDouble', write: 'writeDouble' },
            'byte': { size: 1, read: 'readU8', write: 'writeU8' },
            'short': { size: 2, read: 'readS16', write: 'writeS16' },
            'long': { size: 8, read: 'readS64', write: 'writeS64' },
            'char': { size: 1, read: 'readU8', write: 'writeU8' }
        };
        
        const t = type?.toLowerCase() || 'int';
        return types[t] || types.int;
    },

    /**
     * Convert value to binary pattern for memory scanning
     * @param {string} type - Data type
     * @param {any} value - Value to convert
     * @returns {string} Hex pattern string
     */
    toPattern(type, value) {
        try {
            // 타입 소문자로 변환
            const t = (type || 'uint').toLowerCase();
            
            // 값 유형 확인 및 변환
            let v = value;
            if (typeof v === 'string' && t !== 'string' && t !== 'utf8' && t !== 'utf16') {
                // 문자열을 숫자로 변환 시도
                if (!isNaN(parseFloat(v))) {
                    v = parseFloat(v);
                    // 정수 타입에서는 소수점 자르기
                    if (['int', 'uint', 'short', 'ushort', 'byte', 'int8', 'int16', 'int32', 'uint8', 'uint16', 'uint32'].includes(t)) {
                        v = Math.floor(v);
                    }
                } else {
                    log.error(`Invalid value '${v}' for type '${t}'`);
                    return null;
                }
            }
            
            // 검색 패턴 생성
            let buffer;
            const littleEndian = true; // 대부분의 시스템은 리틀 엔디안
            
            switch (t) {
                case 'byte':
                    if (typeof v !== 'number' || v < 0 || v > 255) {
                        log.error(`Byte value must be a number between 0 and 255: ${v}`);
                        return null;
                    }
                    buffer = new ArrayBuffer(1);
                    new DataView(buffer).setUint8(0, v);
                    break;
                    
                case 'short':
                    if (typeof v !== 'number') {
                        log.error(`Short value must be a number: ${v}`);
                        return null;
                    }
                    buffer = new ArrayBuffer(2);
                    new DataView(buffer).setInt16(0, v, littleEndian);
                    break;
                    
                case 'ushort':
                    if (typeof v !== 'number') {
                        log.error(`Unsigned short value must be a number: ${v}`);
                        return null;
                    }
                    buffer = new ArrayBuffer(2);
                    new DataView(buffer).setUint16(0, v, littleEndian);
                    break;
                    
                case 'int':
                    if (typeof v !== 'number') {
                        log.error(`Int value must be a number: ${v}`);
                        return null;
                    }
                    buffer = new ArrayBuffer(4);
                    new DataView(buffer).setInt32(0, v, littleEndian);
                    break;
                    
                case 'uint':
                    if (typeof v !== 'number') {
                        log.error(`Unsigned int value must be a number: ${v}`);
                        return null;
                    }
                    buffer = new ArrayBuffer(4);
                    new DataView(buffer).setUint32(0, v, littleEndian);
                    break;
                    
                case 'float':
                    if (typeof v !== 'number') {
                        log.error(`Float value must be a number: ${v}`);
                        return null;
                    }
                    buffer = new ArrayBuffer(4);
                    new DataView(buffer).setFloat32(0, v, littleEndian);
                    break;
                    
                case 'double':
                    if (typeof v !== 'number') {
                        log.error(`Double value must be a number: ${v}`);
                        return null;
                    }
                    buffer = new ArrayBuffer(8);
                    new DataView(buffer).setFloat64(0, v, littleEndian);
                    break;
                    
                case 'string':
                case 'utf8':
                    if (typeof v !== 'string') {
                        log.error(`String value must be a string: ${v}`);
                        return null;
                    }
                    
                    let bytes = [];
                    for (let i = 0; i < v.length; i++) {
                        const code = v.charCodeAt(i);
                        if (code < 128) {
                            bytes.push(code);
                        } else if (code < 2048) {
                            bytes.push(192 | (code >> 6), 128 | (code & 63));
                        } else if (code < 65536) {
                            bytes.push(224 | (code >> 12), 128 | ((code >> 6) & 63), 128 | (code & 63));
                        } else {
                            bytes.push(
                                240 | (code >> 18),
                                128 | ((code >> 12) & 63),
                                128 | ((code >> 6) & 63),
                                128 | (code & 63)
                            );
                        }
                    }
                    buffer = new Uint8Array(bytes).buffer;
                    break;
                    
                case 'hex':
                case 'bytes':
                    // 16진수 문자열 패턴을 직접 사용
                    if (typeof v !== 'string') {
                        log.error(`Hex pattern must be a string: ${v}`);
                        return null;
                    }
                    
                    // 공백과 특수 문자 제거
                    const hexPattern = v.replace(/[^0-9a-fA-F?]/g, '');
                    if (hexPattern.length % 2 !== 0) {
                        log.error('Hex pattern must have an even length');
                        return null;
                    }
                    
                    // 2자리씩 공백으로 분리 (XX XX XX 형식)
                    let formattedPattern = '';
                    for (let i = 0; i < hexPattern.length; i += 2) {
                        formattedPattern += hexPattern.substr(i, 2) + ' ';
                    }
                    return formattedPattern.trim();
                    
                default:
                    log.error(`Unsupported type for pattern generation: ${t}`);
                    return null;
            }
            
            // ArrayBuffer를 16진수 문자열로 변환
            const bytes = new Uint8Array(buffer);
            return Array.from(bytes)
                .map(b => b.toString(16).padStart(2, '0'))
                .join(' ');
                
        } catch (e) {
            log.error(`toPattern error for type ${type}, value ${value}: ${e.message}`);
            return null;
        }
    },

    /**
     * Resolve identifier to address
     * @param {string|number} id 
     * @param {string} type 
     * @returns {any} resolved value
     */
    resolve(id, type = 'address') {
        try {
            if (typeof id === 'object') {
                if (id.handle) return id; // Java object
                if (type === 'class' && id.class) return id.class;
                if (type === 'method' && id.class && id.method) return id;
                if (type === 'module' && id.name) return id;
                if (type === 'func' && id.address) return id;
                return null;
            }

            if (typeof id === 'number') {
                if (type === 'address') return ptr(id);
                if (type === 'index') return global.state.logs[id] || null;
            }

            // Handle string format
            if (typeof id === 'string') {
                if (id.startsWith('0x')) return ptr(id);

                // Try to parse as number
                const n = parseInt(id);
                if (!isNaN(n)) {
                    if (type === 'address') return ptr(n);
                    if (type === 'index') return global.state.logs[n] || null;
                }

                // Special identifiers
                if (id === 'lib') {
                    const libName = Process.getModuleByAddress(Process.currentThreadId())?.name;
                    if (libName) return Process.getModuleByName(libName);
                }
            }

            // Try to resolve from logs by index
            const i = parseInt(id);
            if (!isNaN(i) && i >= 0 && i < global.state.logs.length) {
                const item = global.state.logs[i];
                if (type === 'address' && item.value instanceof NativePointer) return item.value;
                if (type === 'module' && item.type === 'module') return item.value;
                if (type === 'class' && item.type === 'class') return item.value;
                if (type === 'method' && item.type === 'method') return item.value;
                if (type === 'func' && item.type === 'func') return item.value;
                return item.value;
            }

            // As a last resort, try to find module by name
            if (type === 'module') {
                try {
                    return Process.getModuleByName(id);
                } catch (e) {
                    return null;
                }
            }

            return null;
        } catch (e) {
            log.error(`resolve(): ${e}`);
            return null;
        }
    },

    /**
     * Generate a timestamp label
     * @returns {string} timestamp string
     */
    timeLabel() {
        const now = new Date();
        return now.toISOString().replace(/T/, ' ').replace(/\..+/, '');
    }
};

module.exports = utils; 