/**
 * 메모리 읽기/쓰기 유틸리티 모듈
 */

// 메모리 읽기/쓰기 유틸리티
const memory = {
    reader: {
        byte: a => a.readU8(),
        short: a => a.readU16(),
        int: a => a.readS32(),
        uint: a => a.readU32(),
        float: a => a.readFloat(),
        string: a => a.readUtf8String(),
        bytes: (a, l = 8) => a.readByteArray(l)
    },

    writer: {
        byte: (a, v) => a.writeU8(v),
        short: (a, v) => a.writeU16(v),
        int: (a, v) => a.writeS32(v),
        uint: (a, v) => a.writeU32(v),
        float: (a, v) => a.writeFloat(v)
    }
};

module.exports = memory; 