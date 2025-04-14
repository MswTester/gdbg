/**
 * History management module
 */

const utils = require('./utils');
const log = require('./logger');

const hist = {
    save(label = '') {
        const finalLabel = label || utils.autoLabel();
        global.state.hist.push({
            index: global.state.hist.length,
            label: finalLabel,
            time: utils.getTime(),
            count: global.state.logs.length,
            data: global.state.logs.map(x => ({ ...x }))
        });
        log.success(`hist[${global.state.hist.length - 1}] "${finalLabel}" saved (${global.state.logs.length} items)`);
    },

    list() {
        if (!global.state.hist.length) return log.info("No history saved");
        
        log.table(global.state.hist, h => 
            `[${h.index}] ${h.label} | ${h.count} items | ${h.time}`
        );
    },

    load(i) {
        const h = global.state.hist[i];
        if (!h) return log.error(`hist.load(): No history at index ${i}`);
        
        global.state.logs.length = 0;
        global.state.logs.push(...h.data.map((x, j) => ({ ...x, index: j })));
        log.success(`hist[${i}] "${h.label}" loaded (${h.count} items)`);
        global.nxt(0);
    },

    clear() {
        global.state.hist.length = 0;
        log.success(`History cleared`);
    },
    
    compare(i, j) {
        const h1 = global.state.hist[i];
        const h2 = global.state.hist[j];
        
        if (!h1 || !h2) return log.error('hist.compare(): Invalid history indices');
        
        const h1Map = new Map(h1.data.map(d => [d.value?.address?.toString() || d.label, d]));
        const h2Map = new Map(h2.data.map(d => [d.value?.address?.toString() || d.label, d]));
        
        const added = [...h2Map.keys()].filter(k => !h1Map.has(k));
        const removed = [...h1Map.keys()].filter(k => !h2Map.has(k));
        
        log.info(`Comparing ${h1.label} <-> ${h2.label}:`);
        log.success(`Added items: ${added.length}`);
        log.warning(`Removed items: ${removed.length}`);
        
        if (added.length > 0) {
            console.log('--- Added items ---');
            added.forEach(k => console.log(h2Map.get(k).label));
        }
        
        if (removed.length > 0) {
            console.log('--- Removed items ---');
            removed.forEach(k => console.log(h1Map.get(k).label));
        }
    }
};

module.exports = hist; 