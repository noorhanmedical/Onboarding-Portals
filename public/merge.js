/* Three-way merge used by both the browser and the server so two people can edit the same clinic at once.
   merge3(base, mine, theirs): base = the version "mine" started from, theirs = the latest saved version.
   - Values only one side changed take that side's change; when both changed the same value, mine wins.
   - Arrays of objects with an `id` merge item by item (adds, removes and edits from both sides survive).
   - Other arrays (audit log, day lists) keep everything either side added and drop what either side removed. */
(function (root) {
  const key = (x) => JSON.stringify(x, (k, v) => (v && typeof v === 'object' && !Array.isArray(v) ? Object.keys(v).sort().reduce((o, kk) => { o[kk] = v[kk]; return o; }, {}) : v));
  const same = (a, b) => key(a) === key(b);
  const isObj = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
  const idList = (a) => Array.isArray(a) && a.every((x) => isObj(x) && x.id != null);

  function merge3(base, mine, theirs) {
    if (same(mine, base)) return theirs;
    if (same(theirs, base) || same(mine, theirs)) return mine;
    if (isObj(mine) && isObj(theirs)) {
      const b = isObj(base) ? base : {};
      const out = {};
      for (const k of new Set([...Object.keys(b), ...Object.keys(mine), ...Object.keys(theirs)])) {
        const inB = k in b, inM = k in mine, inT = k in theirs;
        if (inB && !inM) { if (inT && !same(theirs[k], b[k])) out[k] = theirs[k]; continue; } // I removed it
        if (inB && !inT) { if (inM && !same(mine[k], b[k])) out[k] = mine[k]; continue; } // they removed it
        if (!inT) { out[k] = mine[k]; continue; }
        if (!inM) { out[k] = theirs[k]; continue; }
        out[k] = merge3(inB ? b[k] : undefined, mine[k], theirs[k]);
      }
      return out;
    }
    if (Array.isArray(mine) && Array.isArray(theirs)) {
      const b = Array.isArray(base) ? base : [];
      if (idList(mine) && idList(theirs) && idList(b) && (mine.length || theirs.length)) {
        const B = new Map(b.map((x) => [x.id, x])), M = new Map(mine.map((x) => [x.id, x])), T = new Set(theirs.map((x) => x.id));
        const out = [];
        for (const x of theirs) {
          if (!M.has(x.id)) { if (B.has(x.id) && same(x, B.get(x.id))) continue; out.push(x); continue; } // I deleted it (unless they edited it)
          out.push(merge3(B.get(x.id), M.get(x.id), x));
        }
        mine.forEach((x, i) => {
          if (T.has(x.id)) return;
          if (B.has(x.id) && same(x, B.get(x.id))) return; // they deleted it and I didn't touch it
          const prev = i > 0 ? out.findIndex((y) => y.id === mine[i - 1].id) : -1;
          out.splice(prev + 1, 0, x);
        });
        return out;
      }
      const bk = new Set(b.map(key)), mk = new Set(mine.map(key)), tk = new Set(theirs.map(key));
      const added = mine.filter((x) => !bk.has(key(x)) && !tk.has(key(x)));
      return [...added, ...theirs.filter((x) => !(bk.has(key(x)) && !mk.has(key(x))))];
    }
    return mine;
  }
  const api = { merge3, same, key };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.PxMerge = api;
})(this);
