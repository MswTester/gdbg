/**
 * Utility functions for GDBG
 */

const config = require('./config');
const log = require('./logger');

const utils = {
    /**
     * Format address value
     * @param {any} addr Address value
     * @returns {string} Formatted address string
     */
    formatAddress(addr) {
        if (!addr) return 'null';
        return addr.toString();
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
     * Convert value to pattern for memory scanning
     */
    valueToPattern(val, type) {
        // Convert type to lowercase
        type = type.toLowerCase();
        
        // Check value type and convert if needed
        let value = val;
        
        // Try to convert string to number
        if (typeof value === 'string' && !isNaN(parseFloat(value))) {
            value = parseFloat(value);
            // For integer types, truncate decimal part
            if (type.includes('int') || type === 'uint' || type === 'int') {
                value = Math.floor(value);
            }
        }
        
        let pattern;
        
        try {
            // Create search pattern
            const memory = require('./memory');
            const littleEndian = true; // Most systems are little endian
            
            switch (type) {
                case 'byte':
                case 'int8':
                    pattern = value.toString(16).padStart(2, '0');
                    break;
                    
                case 'short':
                case 'int16':
                    const shortBuf = new ArrayBuffer(2);
                    new DataView(shortBuf).setInt16(0, value, littleEndian);
                    pattern = Array.from(new Uint8Array(shortBuf))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                    
                case 'int':
                case 'int32':
                    const intBuf = new ArrayBuffer(4);
                    new DataView(intBuf).setInt32(0, value, littleEndian);
                    pattern = Array.from(new Uint8Array(intBuf))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                    
                case 'float':
                    const floatBuf = new ArrayBuffer(4);
                    new DataView(floatBuf).setFloat32(0, value, littleEndian);
                    pattern = Array.from(new Uint8Array(floatBuf))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                    
                case 'double':
                    const doubleBuf = new ArrayBuffer(8);
                    new DataView(doubleBuf).setFloat64(0, value, littleEndian);
                    pattern = Array.from(new Uint8Array(doubleBuf))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                    
                case 'uint':
                case 'uint32':
                    const uintBuf = new ArrayBuffer(4);
                    new DataView(uintBuf).setUint32(0, value, littleEndian);
                    pattern = Array.from(new Uint8Array(uintBuf))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                    
                case 'uint8':
                    pattern = (value & 0xFF).toString(16).padStart(2, '0');
                    break;
                    
                case 'uint16':
                    const uint16Buf = new ArrayBuffer(2);
                    new DataView(uint16Buf).setUint16(0, value, littleEndian);
                    pattern = Array.from(new Uint8Array(uint16Buf))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                    
                case 'int64':
                case 'uint64':
                case 'long':
                    // This is approximation for 64-bit values
                    const longBuf = new ArrayBuffer(8);
                    const longView = new DataView(longBuf);
                    // Split into two 32-bit values
                    const low32 = value & 0xFFFFFFFF;
                    const high32 = Math.floor(value / 0x100000000);
                    longView.setUint32(0, low32, littleEndian);
                    longView.setUint32(4, high32, littleEndian);
                    pattern = Array.from(new Uint8Array(longBuf))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                    
                case 'string':
                case 'ascii':
                case 'utf8':
                    // Use hex string pattern directly
                    if (typeof value === 'string') {
                        if (value.startsWith('0x')) {
                            // Remove 0x prefix
                            value = value.substring(2);
                        }
                        
                        // Remove spaces and special characters
                        value = value.replace(/[^0-9a-fA-F]/g, '');
                        
                        if (value.length % 2 !== 0) {
                            value = value + '0';  // Pad if odd length
                        }
                        
                        // Split into XX XX XX format
                        pattern = value.match(/.{2}/g).join(' ');
                    } else {
                        // Convert non-string to string
                        const str = String(value);
                        pattern = Array.from(str)
                            .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
                            .join(' ');
                    }
                    break;
                    
                case 'hex':
                    // Convert ArrayBuffer to hex string
                    if (value instanceof ArrayBuffer) {
                        pattern = Array.from(new Uint8Array(value))
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join(' ');
                    } else if (typeof value === 'string') {
                        // Assume it's already a hex string, just format it
                        // Remove 0x prefix if exists
                        if (value.startsWith('0x')) {
                            value = value.substring(2);
                        }
                        
                        // Remove spaces and non-hex chars
                        value = value.replace(/[^0-9a-fA-F]/g, '');
                        
                        if (value.length % 2 !== 0) {
                            value = value + '0';  // Pad if odd length
                        }
                        
                        // Split into pairs
                        pattern = value.match(/.{2}/g).join(' ');
                    } else {
                        log.error(`Can't convert ${typeof value} to hex pattern`);
                        return null;
                    }
                    break;
                
                default:
                    log.error(`Unsupported type: ${type}`);
                    return null;
            }
            
            return pattern;
        } catch (e) {
            log.error(`Failed to create pattern: ${e.message}`);
            return null;
        }
    },

    /**
     * Resolve a pointer from various inputs
     * @param {string|number|object} i Input value (index, address, or object)
     * @param {string} t Expected type
     * @returns {any} Resolved object or address
     */
    resolve(i, t) {
        // Special case for ptr type
        if (t === 'ptr') {
            // Try to resolve from global.state.logs
            if (!isNaN(parseInt(i)) && global.state.logs[i]) {
                return global.state.logs[i].value;
            }
            
            // Try to parse as hex address
            if (typeof i === 'string' && i.toLowerCase().startsWith('0x')) {
                try {
                    return ptr(i);
                } catch (e) {
                    log.error(`Failed to parse address: ${i}`);
                    return null;
                }
            }
            
            // Try to use directly if it's already a pointer
            if (i && typeof i === 'object' && i.toString().includes('0x')) {
                return i;
            }
            
            // Try to convert to string and then ptr
            try {
                return ptr(String(i));
            } catch (e) {
                log.error(`Failed to convert to pointer: ${i}`);
                return null;
            }
        }
        
        // For other types, use the value directly
        return i;
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