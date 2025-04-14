/**
 * Listing module
 */

const utils = require('./utils');
const log = require('./logger');

const list = {
    class(k = '') {
        Java.perform(() => {
            try {
                log.info(`Searching classes: "${k || 'all'}"`);
                const r = Java.enumerateLoadedClassesSync()
                    .filter(c => c.toLowerCase().includes(k.toLowerCase()));
                
                global.state.logs.length = 0;
                r.forEach((c, i) =>
                    global.state.logs.push({ index: i, label: c, value: c, type: 'class' })
                );
                
                log.success(`Found ${r.length} classes`);
                global.nxt(0);
            } catch (e) {
                log.error(`list.class(): ${e}`);
            }
        });
    },

    method(cls, k = '') {
        const c = utils.resolve(cls, 'class');
        if (!c) return log.error(`list.method(): Invalid class @ ${cls}`);
        
        Java.perform(() => {
            try {
                log.info(`Searching methods in ${c}: "${k || 'all'}"`);
                const clz = Java.use(c);
                const m = Object.getOwnPropertyNames(clz.__proto__)
                    .filter(x => clz[x]?.overloads)
                    .filter(x => !k || x.toLowerCase().includes(k.toLowerCase()));
                
                global.state.logs.length = 0;
                m.forEach((m, i) =>
                    global.state.logs.push({
                        index: i,
                        label: `[${c.split('.').pop()}] ${m}`,
                        value: { class: c, method: m },
                        type: 'method'
                    })
                );
                
                log.success(`Found ${m.length} methods`);
                global.nxt(0);
            } catch (e) {
                log.error(`list.method(): ${e}`);
            }
        });
    },

    module(k = '') {
        try {
            log.info(`Searching modules: "${k || 'all'}"`);
            const mods = Process.enumerateModules()
                .filter(m => m.name.toLowerCase().includes(k.toLowerCase()));
            
            global.state.logs.length = 0;
            mods.forEach((m, i) =>
                global.state.logs.push({
                    index: i,
                    label: `${utils.formatAddress(m.base)} | ${m.name} (${utils.formatSize(m.size)})`,
                    value: { name: m.name, base: m.base, size: m.size },
                    type: 'module'
                })
            );
            
            log.success(`Found ${mods.length} modules`);
            global.nxt(0);
        } catch (e) {
            log.error(`list.module(): ${e}`);
        }
    },

    export(lib, k = '') {
        const m = utils.resolve(lib, 'module');
        if (!m) return log.error(`list.export(): Invalid module @ ${lib}`);
        
        try {
            log.info(`Searching exports in ${m.name}: "${k || 'all'}"`);
            const e = Module.enumerateExportsSync(m.name)
                .filter(x => x.name.toLowerCase().includes(k.toLowerCase()));
            
            global.state.logs.length = 0;
            e.forEach((f, i) =>
                global.state.logs.push({
                    index: i,
                    label: `${utils.formatAddress(f.address)} | ${f.name} (${f.type})`,
                    value: { ...f, lib: m.name, base: m.base },
                    type: 'func'
                })
            );
            
            log.success(`Found ${e.length} exports`);
            global.nxt(0);
        } catch (e) {
            log.error(`list.export(): ${e}`);
        }
    }
};

module.exports = list; 