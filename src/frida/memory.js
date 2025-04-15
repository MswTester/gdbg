/**
 * Memory read/write utility module
 */

// Memory read/write utilities
const reader = {
    byte: addr => addr.readS8(),
    int8: addr => addr.readS8(),
    uint8: addr => addr.readU8(),
    short: addr => addr.readS16(),
    int16: addr => addr.readS16(),
    uint16: addr => addr.readU16(),
    int: addr => addr.readS32(),
    int32: addr => addr.readS32(),
    uint: addr => addr.readU32(),
    uint32: addr => addr.readU32(),
    long: addr => addr.readS64(),
    int64: addr => addr.readS64(),
    uint64: addr => addr.readU64(),
    float: addr => addr.readFloat(),
    double: addr => addr.readDouble(),
    pointer: addr => addr.readPointer(),
    string: addr => addr.readUtf8String()
};

const writer = {
    byte: (addr, val) => addr.writeS8(val),
    int8: (addr, val) => addr.writeS8(val),
    uint8: (addr, val) => addr.writeU8(val),
    short: (addr, val) => addr.writeS16(val),
    int16: (addr, val) => addr.writeS16(val),
    uint16: (addr, val) => addr.writeU16(val),
    int: (addr, val) => addr.writeS32(val),
    int32: (addr, val) => addr.writeS32(val),
    uint: (addr, val) => addr.writeU32(val),
    uint32: (addr, val) => addr.writeU32(val),
    long: (addr, val) => addr.writeS64(val),
    int64: (addr, val) => addr.writeS64(val),
    uint64: (addr, val) => addr.writeU64(val),
    float: (addr, val) => addr.writeFloat(val),
    double: (addr, val) => addr.writeDouble(val),
    pointer: (addr, val) => addr.writePointer(val),
    string: (addr, val) => addr.writeUtf8String(val)
};

module.exports = {
    reader,
    writer
}; 