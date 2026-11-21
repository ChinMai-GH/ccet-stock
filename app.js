(function () {
  'use strict';

  // ข้อมูลอยู่ในโฟลเดอร์เดียวกับหน้าเว็บบน GitHub Pages (ถูกเข้ารหัสไว้ทั้งหมด)
  var KEY_URL = 'data/key.json';
  var STOCK_URL = 'data/stock.enc';
  var PHOTO_DIR = 'p/';
  var THUMB_DIR = 't/';          // รูปย่อสำหรับรายการ (~5 KB/รูป)
  var AREA_PREF = 'ccet_stock_area_off';  // Area ที่ยกเลิกไว้ (จำในเครื่อง)
  var AREA_ORDER = ['L8', 'H1', 'L6', 'H2']; // ลำดับปุ่ม Area (Area อื่นต่อท้ายตามตัวอักษร)
  var AREA_DEFAULT_ON = ['L8', 'H1'];        // เปิดเว็บครั้งแรก เลือกไว้แค่นี้
  var NO_PHOTO = '__nophoto';                // ตัวเลือก "ไม่มีรูป" ใน Dropdown สถานะ
  var THUMBS_PREF = 'ccet_stock_thumbs'; // '1' = แสดงรูปในรายการ, '0' = ไม่แสดง (ประหยัดเน็ต)
  var REMEMBER_KEY = 'ccet_stock_master';
  // ระดับผู้ดูแล: Vendor / ราคา / ถ่ายรูป (กุญแจแยก)
  var PRICE_KEY_URL = 'data/admin-key.json';
  var PRICE_URL = 'data/admin.enc';
  var REMEMBER_PRICE = 'ccet_stock_admin';
  var GITHUB_API = 'https://api.github.com';

  var PAGE_SIZE = 50;
  var STATUS_CHECK_MS = 5 * 60 * 1000;
  var MAGIC = [0x43, 0x43, 0x53, 0x31]; // "CCS1"

  var STATUSES = [
    { key: '', label: 'ทั้งหมด' },
    { key: 'Idle', label: 'Idle', cls: 's-idle' },
    { key: 'Slow Moving', label: 'Slow Moving', cls: 's-slow' },
    { key: 'Moving', label: 'Moving', cls: 's-moving' },
    { key: 'No Receive', label: 'No Receive', cls: 's-norecv' }
  ];

  var state = {
    keys: null,       // { enc, mac, name } CryptoKey
    items: [],
    filtered: [],
    shown: 0,
    fingerprint: null,
    syncedAt: null,
    interval: 60,
    status: '',
    areas: [],        // รายชื่อ Area ทั้งหมดจากข้อมูล
    areaOff: {},      // Area ที่ผู้ใช้กดยกเลิก (ไม่เลือก)
    query: '',
    priceKeys: null,   // { enc, mac } — null = ยังไม่ปลดล็อกราคา
    prices: null,      // { "PART|AREA": [ราคา, "สกุลเงิน", "Vendor"] } — null = ยังไม่ปลดล็อกผู้ดูแล
    upload: null,      // ข้อมูลสำหรับส่งรูปเข้า inbox
    priceRate: 30,
    priceFingerprint: null
  };

  var $ = function (id) { return document.getElementById(id); };
  var subtle = window.crypto && window.crypto.subtle;

  // ================= Crypto =================

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function toHex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += ('0' + bytes[i].toString(16)).slice(-2);
    return s;
  }

  function importPair(raw) { // raw 64 bytes -> { enc, mac }
    return Promise.all([
      subtle.importKey('raw', raw.slice(0, 32), { name: 'AES-CBC' }, false, ['decrypt']),
      subtle.importKey('raw', raw.slice(32, 64), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
    ]).then(function (k) { return { enc: k[0], mac: k[1] }; });
  }

  /** กุญแจผู้ดูแล: ใช้ทั้งถอดรหัสข้อมูล และเข้ารหัสรูปที่จะส่ง */
  function importPairFull(raw) {
    return Promise.all([
      subtle.importKey('raw', raw.slice(0, 32), { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']),
      subtle.importKey('raw', raw.slice(32, 64), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
    ]).then(function (k) { return { enc: k[0], mac: k[1] }; });
  }

  /** เข้ารหัสรูปแบบเดียวกับโปรแกรม: "CCS1" | IV | ciphertext | HMAC */
  function encryptFile(plain, keys) {
    var iv = window.crypto.getRandomValues(new Uint8Array(16));
    return subtle.encrypt({ name: 'AES-CBC', iv: iv }, keys.enc, plain).then(function (ct) {
      var c = new Uint8Array(ct);
      var data = new Uint8Array(4 + 16 + c.length);
      data.set(MAGIC, 0);
      data.set(iv, 4);
      data.set(c, 20);
      return subtle.sign('HMAC', keys.mac, data).then(function (mac) {
        var out = new Uint8Array(data.length + 32);
        out.set(data, 0);
        out.set(new Uint8Array(mac), data.length);
        return out;
      });
    });
  }

  function importMaster(raw) { // raw 96 bytes -> { enc, mac, name }
    return Promise.all([
      importPair(raw.slice(0, 64)),
      subtle.importKey('raw', raw.slice(64, 96), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    ]).then(function (k) { return { enc: k[0].enc, mac: k[0].mac, name: k[1] }; });
  }

  /** ถอดรหัสไฟล์ "CCS1" | IV | ciphertext | HMAC — ถ้ากุญแจผิดจะ reject ด้วย 'badkey' */
  function decryptFile(buf, keys) {
    var data = new Uint8Array(buf);
    if (data.length < 68) return Promise.reject(new Error('badfile'));
    for (var i = 0; i < 4; i++) if (data[i] !== MAGIC[i]) return Promise.reject(new Error('badfile'));
    var macStart = data.length - 32;
    return subtle.verify('HMAC', keys.mac, data.slice(macStart), data.slice(0, macStart)).then(function (ok) {
      if (!ok) throw new Error('badkey');
      return subtle.decrypt({ name: 'AES-CBC', iv: data.slice(4, 20) }, keys.enc, data.slice(20, macStart));
    });
  }

  function unlockWithPassword(password, keyUrl) {
    return fetch(keyUrl || KEY_URL, { cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error('nokey');
      return r.json();
    }).then(function (kf) {
      return subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
        .then(function (base) {
          return subtle.deriveBits({ name: 'PBKDF2', salt: b64ToBytes(kf.salt), iterations: kf.iter, hash: 'SHA-256' }, base, 512);
        })
        .then(function (bits) { return importPair(new Uint8Array(bits)); })
        .then(function (pk) { return decryptFile(b64ToBytes(kf.wrapped).buffer, pk); })
        .then(function (master) { return new Uint8Array(master); });
    });
  }

  function gunzipToText(buf) {
    if (typeof DecompressionStream === 'undefined') return Promise.reject(new Error('oldbrowser'));
    var stream = new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Response(stream).text();
  }

  // ================= Data =================

  function loadStock(force) {
    return fetch(STOCK_URL, { cache: 'no-cache' }).then(function (r) {
      if (r.status === 404) throw new Error('nodata');
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.arrayBuffer();
    }).then(function (buf) {
      var bytes = new Uint8Array(buf);
      var fp = toHex(bytes.slice(bytes.length - 8));
      if (!force && fp === state.fingerprint) return false; // ไม่มีข้อมูลใหม่
      return decryptFile(buf, state.keys)
        .then(gunzipToText)
        .then(function (text) {
          state.fingerprint = fp;
          prepare(JSON.parse(text));
          return true;
        });
    });
  }

  // ================= Start / Login =================

  function start() {
    if (!subtle) {
      showLogin('เบราว์เซอร์นี้ไม่รองรับ กรุณาใช้ Chrome หรือ Safari รุ่นใหม่');
      return;
    }
    var saved = null;
    try { saved = localStorage.getItem(REMEMBER_KEY); } catch (e) { }
    if (!saved) { showLogin(); return; }

    importMaster(b64ToBytes(saved)).then(function (keys) {
      state.keys = keys;
      showMain();
      return loadStock(true);
    }).then(initPrice).catch(function (e) { handleLoadError(e, true); });
  }

  function handleLoadError(e, fromSaved) {
    var msg = e && e.message;
    if (msg === 'badkey') {
      forget();
      showLogin(fromSaved ? 'รหัสผ่าน/กุญแจถูกเปลี่ยน กรุณาใส่รหัสผ่านใหม่' : 'รหัสผ่านไม่ถูกต้อง');
    } else if (msg === 'nodata') {
      $('syncedAt').textContent = 'ยังไม่มีข้อมูล กรุณารอโปรแกรมอัปโหลดรอบแรก';
    } else if (msg === 'oldbrowser') {
      showLogin('เบราว์เซอร์นี้เก่าเกินไป กรุณาอัปเดต Chrome / Safari');
    } else {
      toast('โหลดข้อมูลไม่สำเร็จ ลองใหม่อีกครั้ง');
    }
  }

  function showLogin(error) {
    $('mainView').hidden = true;
    $('detailView').hidden = true;
    $('loginView').hidden = false;
    $('loginPassword').value = '';
    var err = $('loginError');
    err.textContent = error || '';
    err.hidden = !error;
    setTimeout(function () { $('loginPassword').focus(); }, 50);
  }

  function showMain() {
    $('loginView').hidden = true;
    $('mainView').hidden = false;
  }

  function forget() {
    state.keys = null;
    state.fingerprint = null;
    state.items = [];
    clearPhotoCache();
    clearThumbCache();
    try { localStorage.removeItem(REMEMBER_KEY); } catch (e) { }
    forgetPrice();
  }

  $('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();
    var btn = $('loginBtn');
    var err = $('loginError');
    btn.disabled = true;
    btn.textContent = 'กำลังตรวจสอบ ...';
    err.hidden = true;

    unlockWithPassword($('loginPassword').value).then(function (master) {
      if ($('rememberMe').checked) {
        try { localStorage.setItem(REMEMBER_KEY, bytesToB64(master)); } catch (x) { }
      }
      return importMaster(master);
    }).then(function (keys) {
      state.keys = keys;
      showMain();
      return loadStock(true);
    }).then(initPrice).catch(function (x) {
      var m = x && x.message;
      if (m === 'badkey') err.textContent = 'รหัสผ่านไม่ถูกต้อง';
      else if (m === 'nokey') err.textContent = 'ยังไม่มีข้อมูลบนเว็บ (โปรแกรมยังไม่ได้อัปโหลด)';
      else if (m === 'oldbrowser') err.textContent = 'เบราว์เซอร์เก่าเกินไป กรุณาอัปเดต';
      else err.textContent = 'เชื่อมต่อไม่ได้ ลองใหม่อีกครั้ง';
      err.hidden = false;
      if (!$('mainView').hidden) showLogin(err.textContent);
    }).then(function () {
      btn.disabled = false;
      btn.textContent = 'เข้าสู่ระบบ';
    });
  });

  $('logoutBtn').addEventListener('click', function () {
    if (!confirm('ออกจากระบบ? (เครื่องนี้จะลืมรหัสผ่าน)')) return;
    forget();
    showLogin();
  });

  // เช็คข้อมูลรอบใหม่ทุก 5 นาที และทุกครั้งที่กลับมาเปิดหน้าเว็บ
  function refresh() {
    if ($('mainView').hidden || !state.keys) return;
    loadStock(false).then(function (changed) {
      if (changed) toast('อัปเดตข้อมูลล่าสุดแล้ว');
      else updateStale();
      if (state.priceKeys) return loadPrices(false).catch(function () { });
    }).catch(function (e) {
      if (e && e.message === 'badkey') handleLoadError(e, true);
    });
  }
  setInterval(refresh, STATUS_CHECK_MS);
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) refresh();
  });

  // ================= Prepare / Filter =================

  function prepare(data) {
    var items = data.items || [];
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      it._base = [it.p, it.d, it.s, it.l, it.f].join(' ').toUpperCase();
      it._idx = it._base;
    }
    state.items = items;
    buildIndex();
    state.syncedAt = data.syncedAt;
    state.interval = data.interval || 60;
    $('syncedAt').textContent = 'ข้อมูล ณ ' + formatDateTime(data.syncedAt);
    updateStale();

    state.areas = (data.areas || []).slice().sort(function (x, y) {
      var ix = AREA_ORDER.indexOf(x), iy = AREA_ORDER.indexOf(y);
      if (ix < 0) ix = 999;
      if (iy < 0) iy = 999;
      return ix !== iy ? ix - iy : (x < y ? -1 : x > y ? 1 : 0);
    });
    state.areaOff = {};
    var saved = null;
    try { saved = JSON.parse(localStorage.getItem(AREA_PREF)); } catch (e) { }
    if (saved && saved.forEach) {
      saved.forEach(function (a) { if (state.areas.indexOf(a) >= 0) state.areaOff[a] = true; });
    } else {
      // ยังไม่เคยเลือก: เปิดไว้แค่ L8 กับ H1
      state.areas.forEach(function (a) { if (AREA_DEFAULT_ON.indexOf(a) < 0) state.areaOff[a] = true; });
    }

    applyFilter();
  }

  function updateStale() {
    var m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})/.exec(state.syncedAt || '');
    if (!m) { $('staleBanner').hidden = true; return; }
    var t = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]);
    var limitMin = state.interval * 2 + 15;
    $('staleBanner').hidden = (Date.now() - t.getTime()) < limitMin * 60000;
  }

  function applyFilter() {
    var tokens = state.query.toUpperCase().split(/\s+/).filter(Boolean);
    var base = [];
    var counts = {};
    STATUSES.forEach(function (s) { counts[s.key] = 0; });
    counts[NO_PHOTO] = 0;

    var areaCounts = {};
    state.areas.forEach(function (a) { areaCounts[a] = 0; });

    for (var i = 0; i < state.items.length; i++) {
      var it = state.items[i];
      var ok = true;
      for (var t = 0; t < tokens.length; t++) {
        if (it._idx.indexOf(tokens[t]) < 0) { ok = false; break; }
      }
      if (!ok) continue;
      // ตัวเลขบนปุ่ม Area = ตามคำค้นหา + สถานะที่เลือก
      if (matchStatus(it)) areaCounts[it.a] = (areaCounts[it.a] || 0) + 1;
      // ตัวเลขใน Dropdown สถานะ = ตามคำค้นหา + Area ที่เลือก
      if (state.areaOff[it.a]) continue;
      base.push(it);
      counts['']++;
      if (counts[it.st] !== undefined) counts[it.st]++;
      if (!it.ph) counts[NO_PHOTO]++;
    }

    state.filtered = state.status ? base.filter(matchStatus) : base;

    renderStatusSelect(counts);
    renderAreaChips(areaCounts);
    var noArea = state.areas.length > 0 && state.areas.every(function (a) { return state.areaOff[a]; });
    $('emptyMsg').textContent = noArea ? 'กรุณาเลือก Area อย่างน้อย 1 อัน' : 'ไม่พบรายการที่ค้นหา';
    $('resultInfo').textContent = 'พบ ' + state.filtered.length.toLocaleString() + ' รายการ';
    $('emptyMsg').hidden = state.filtered.length > 0 || state.items.length === 0;

    $('list').textContent = '';
    state.shown = 0;
    renderMore();
  }

  // ================= Render =================

  function matchStatus(it) {
    if (!state.status) return true;
    if (state.status === NO_PHOTO) return !it.ph;
    return it.st === state.status;
  }

  function renderStatusSelect(counts) {
    var sel = $('statusSelect');
    sel.textContent = '';
    STATUSES.forEach(function (s) {
      var o = document.createElement('option');
      o.value = s.key;
      o.textContent = (s.key ? s.label : 'ทุกสถานะ') + ' (' + (counts[s.key] || 0).toLocaleString() + ')';
      sel.appendChild(o);
    });
    var np = document.createElement('option');
    np.value = NO_PHOTO;
    np.textContent = '📷 ไม่มีรูป (' + (counts[NO_PHOTO] || 0).toLocaleString() + ')';
    sel.appendChild(np);
    sel.value = state.status;
    sel.className = !state.status ? '' : state.status === NO_PHOTO ? 'picked s-nophoto' : 'picked ' + statusClass(state.status);
  }

  function renderAreaChips(counts) {
    var box = $('areaChips');
    box.textContent = '';
    state.areas.forEach(function (a) {
      var b = document.createElement('button');
      b.type = 'button';
      var on = !state.areaOff[a];
      b.className = 'chip' + (on ? ' active' : '');
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      b.textContent = a + ' (' + (counts[a] || 0).toLocaleString() + ')';
      b.addEventListener('click', function () {
        if (state.areaOff[a]) delete state.areaOff[a]; else state.areaOff[a] = true;
        try { localStorage.setItem(AREA_PREF, JSON.stringify(Object.keys(state.areaOff))); } catch (e) { }
        applyFilter();
      });
      box.appendChild(b);
    });
  }

  function renderMore() {
    var list = $('list');
    var end = Math.min(state.shown + PAGE_SIZE, state.filtered.length);
    var frag = document.createDocumentFragment();
    for (var i = state.shown; i < end; i++) frag.appendChild(makeCard(state.filtered[i]));
    list.appendChild(frag);
    state.shown = end;
  }

  function statusClass(st) {
    for (var i = 0; i < STATUSES.length; i++) {
      if (STATUSES[i].key === st && STATUSES[i].cls) return STATUSES[i].cls;
    }
    return 's-norecv';
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  function makeCard(it) {
    var cls = statusClass(it.st);
    var withThumb = thumbsOn();
    var card = el('div', 'card ' + cls + (withThumb ? ' with-thumb' : ''));
    var body = withThumb ? el('div', 'card-body') : card;

    var top = el('div', 'card-top');
    if (withThumb) {
      // โหมดรูป: รูปอยู่ด้านขวาแทนป้ายสถานะ — สถานะย้ายมาเป็นป้ายเล็กต่อท้าย Part
      var pl = el('div', 'part', it.p + ' ');
      pl.appendChild(el('span', 'badge mini ' + cls, it.st));
      top.appendChild(pl);
    } else {
      top.appendChild(el('div', 'part', it.p + (it.ph ? ' 📷' : '')));
      top.appendChild(el('span', 'badge ' + cls, it.st));
    }
    body.appendChild(top);

    if (it.d) body.appendChild(el('div', 'desc', it.d));
    if (it.s) body.appendChild(el('div', 'spec', it.s));

    var bottom = el('div', 'card-bottom');
    var qty = el('span', null, 'Stock: ');
    qty.appendChild(el('b', it.q <= 0 ? 'qty-zero' : null, formatQty(it.q)));
    bottom.appendChild(qty);
    bottom.appendChild(labelValue('Loc: ', location(it)));
    bottom.appendChild(labelValue('Area: ', it.a));
    var vd = vendorOf(it);
    if (vd) bottom.appendChild(labelValue('Vendor: ', vd));
    var pr = priceOf(it);
    if (hasPrice(pr)) {
      var ps = labelValue('ราคา: ', formatPrice(pr, true));
      ps.className = 'price';
      bottom.appendChild(ps);
    }
    body.appendChild(bottom);

    if (withThumb) {
      card.appendChild(body);
      card.appendChild(makeThumb(it));
    }

    card.addEventListener('click', function () { openDetail(it); });
    return card;
  }

  // ================= รูปย่อในรายการ =================

  var thumbCache = {};     // part -> blob URL (ไฟล์เล็ก เก็บไว้ทั้ง session ล้างตอนออกจากระบบ)
  var thumbQueue = [];
  var thumbActive = 0;
  var THUMB_PARALLEL = 4;
  var thumbObserver = ('IntersectionObserver' in window)
    ? new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (!e.isIntersecting) return;
          thumbObserver.unobserve(e.target);
          queueThumb(e.target);
        });
      }, { rootMargin: '200px' })
    : null;

  function thumbsOn() {
    var v = null;
    try { v = localStorage.getItem(THUMBS_PREF); } catch (e) { }
    if (v === '1') return true;
    if (v === '0') return false;
    // ยังไม่เคยเลือก: เปิดรูป ยกเว้นมือถือเปิดโหมดประหยัดดาต้า
    var c = navigator.connection;
    return !(c && c.saveData);
  }

  function setThumbsOn(on) {
    try { localStorage.setItem(THUMBS_PREF, on ? '1' : '0'); } catch (e) { }
    updateThumbBtn();
    rerenderList();
  }

  function updateThumbBtn() {
    var on = thumbsOn();
    var b = $('thumbBtn');
    b.textContent = on ? '🖼 รูป' : '🚫 รูป';
    b.setAttribute('aria-pressed', on ? 'true' : 'false');
    b.title = on ? 'กำลังแสดงรูปในรายการ (กดเพื่อปิด ประหยัดเน็ต)' : 'ไม่แสดงรูปในรายการ (กดเพื่อเปิด)';
    b.classList.toggle('off', !on);
  }

  /** วาดรายการใหม่โดยคงจำนวนที่เลื่อนดูไว้และตำแหน่งเลื่อน */
  function rerenderList() {
    var y = window.scrollY;
    var count = state.shown;
    $('list').textContent = '';
    thumbQueue = [];
    state.shown = 0;
    while (state.shown < count && state.shown < state.filtered.length) renderMore();
    window.scrollTo(0, y);
  }

  function makeThumb(it) {
    var box = el('div', 'thumb');
    if (!it.ph) { box.classList.add('none'); return box; }
    if (!it.tb) { box.classList.add('pending'); box.textContent = '📷'; return box; } // มีรูปเต็มแต่รูปย่อยังไม่ขึ้น
    box._part = it.p;
    if (thumbCache[it.p]) { setThumbImg(box, thumbCache[it.p]); return box; }
    box.classList.add('loading');
    if (thumbObserver) thumbObserver.observe(box); else queueThumb(box);
    return box;
  }

  function setThumbImg(box, url) {
    box.classList.remove('loading');
    box.textContent = '';
    var img = document.createElement('img');
    img.alt = '';
    img.src = url;
    box.appendChild(img);
  }

  function queueThumb(box) {
    thumbQueue.push(box);
    pumpThumbs();
  }

  function pumpThumbs() {
    while (thumbActive < THUMB_PARALLEL && thumbQueue.length) {
      var box = thumbQueue.shift();
      if (!box.isConnected) continue; // รายการถูกวาดใหม่ไปแล้ว
      thumbActive++;
      loadThumb(box._part).then(function (b) {
        return function (url) { if (b.isConnected) setThumbImg(b, url); };
      }(box), function (b) {
        return function () { b.classList.remove('loading'); b.classList.add('pending'); b.textContent = '📷'; };
      }(box)).then(function () {
        thumbActive--;
        pumpThumbs();
      });
    }
  }

  function loadThumb(part) {
    if (thumbCache[part]) return Promise.resolve(thumbCache[part]);
    var keys = state.keys;
    return photoName(part).then(function (name) {
      return fetch(THUMB_DIR + name + '.enc');
    }).then(function (r) {
      if (!r.ok) throw new Error('nothumb');
      return r.arrayBuffer();
    }).then(function (buf) {
      return decryptFile(buf, keys);
    }).then(function (jpg) {
      if (state.keys !== keys) throw new Error('loggedout');
      var url = URL.createObjectURL(new Blob([jpg], { type: 'image/jpeg' }));
      thumbCache[part] = url;
      return url;
    });
  }

  function clearThumbCache() {
    for (var k in thumbCache) URL.revokeObjectURL(thumbCache[k]);
    thumbCache = {};
    thumbQueue = [];
  }

  $('thumbBtn').addEventListener('click', function () { setThumbsOn(!thumbsOn()); });
  updateThumbBtn();

  function labelValue(label, value) {
    var s = el('span', null, label);
    s.appendChild(el('b', null, value || '-'));
    return s;
  }

  function location(it) {
    var parts = [];
    if (it.f) parts.push(it.f);
    if (it.l) parts.push(it.l);
    return parts.join(' / ');
  }

  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function (entries) {
      if (entries[0].isIntersecting && state.shown < state.filtered.length) renderMore();
    }, { rootMargin: '600px' }).observe($('sentinel'));
  } else {
    window.addEventListener('scroll', function () {
      if (window.innerHeight + window.scrollY > document.body.offsetHeight - 600 &&
          state.shown < state.filtered.length) renderMore();
    });
  }

  // ================= Search events =================

  var searchTimer = null;
  $('searchBox').addEventListener('input', function () {
    var v = this.value;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function () {
      state.query = v.trim();
      applyFilter();
      window.scrollTo(0, 0);
    }, 200);
  });
  $('searchBox').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') this.blur();
  });

  $('statusSelect').addEventListener('change', function () {
    state.status = this.value;
    applyFilter();
    window.scrollTo(0, 0);
  });

  // ================= Photos (encrypted) =================

  var photoCache = {};      // part -> blob URL
  var photoOrder = [];
  var PHOTO_CACHE_MAX = 30;
  var currentPhotoPart = null;

  function clearPhotoCache() {
    for (var k in photoCache) URL.revokeObjectURL(photoCache[k]);
    photoCache = {};
    photoOrder = [];
  }

  function photoName(part) {
    return subtle.sign('HMAC', state.keys.name, new TextEncoder().encode(part.toUpperCase()))
      .then(function (sig) { return toHex(new Uint8Array(sig).slice(0, 16)); });
  }

  function loadPhoto(part) {
    if (photoCache[part]) return Promise.resolve(photoCache[part]);
    return photoName(part).then(function (name) {
      return fetch(PHOTO_DIR + name + '.enc');
    }).then(function (r) {
      if (!r.ok) throw new Error('nophoto');
      return r.arrayBuffer();
    }).then(function (buf) {
      return decryptFile(buf, state.keys);
    }).then(function (jpg) {
      var url = URL.createObjectURL(new Blob([jpg], { type: 'image/jpeg' }));
      photoCache[part] = url;
      photoOrder.push(part);
      if (photoOrder.length > PHOTO_CACHE_MAX) {
        var old = photoOrder.shift();
        URL.revokeObjectURL(photoCache[old]);
        delete photoCache[old];
      }
      return url;
    });
  }

  // ================= Detail =================

  var detailOpen = false;

  var currentItem = null;

  function openDetail(it) {
    currentItem = it;
    updatePhotoActions(it);
    var cls = statusClass(it.st);
    $('detailTitle').textContent = it.p;

    var img = $('detailPhoto');
    img.hidden = true;
    img.removeAttribute('src');
    var noPhoto = $('noPhoto');
    currentPhotoPart = it.p;
    if (it.ph) {
      noPhoto.textContent = 'กำลังโหลดรูป ...';
      noPhoto.hidden = false;
      loadPhoto(it.p).then(function (url) {
        if (currentPhotoPart !== it.p) return;
        img.src = url;
        img.hidden = false;
        noPhoto.hidden = true;
      }).catch(function () {
        if (currentPhotoPart !== it.p) return;
        noPhoto.textContent = 'โหลดรูปไม่ได้';
      });
    } else {
      noPhoto.textContent = 'ไม่มีรูป';
      noPhoto.hidden = false;
    }

    var badge = $('detailStatus');
    badge.className = 'badge big ' + cls;
    badge.textContent = it.st;

    var dl = $('detailFields');
    dl.textContent = '';
    addField(dl, 'Part No', it.p);
    addField(dl, 'Description', it.d);
    addField(dl, 'Spec', it.s);
    addField(dl, 'Stock คงเหลือ', formatQty(it.q));
    var pr = priceOf(it);
    if (state.prices) addField(dl, 'Vendor', vendorOf(it));
    if (hasPrice(pr)) {
      addField(dl, 'ราคาล่าสุด', formatPrice(pr, false));
      if (pr[1] === 'US') addField(dl, 'ราคา (THB)', formatThb(pr) + '  (THB/USD ' + state.priceRate + ')');
    }
    addField(dl, 'Made Area', it.a);
    addField(dl, 'Floor', it.f);
    addField(dl, 'Location', it.l);
    addField(dl, 'รับเข้าล่าสุด', it.r ? formatDate(it.r) : 'ไม่มีประวัติรับเข้า');
    addField(dl, 'เบิกใน 365 วัน', it.i.toLocaleString() + ' ครั้ง');

    $('detailView').hidden = false;
    $('detailView').scrollTop = 0;
    document.body.style.overflow = 'hidden';
    if (!detailOpen) {
      detailOpen = true;
      history.pushState({ detail: true }, '');
    }
  }

  function closeDetail() {
    $('detailView').hidden = true;
    $('zoomView').hidden = true;
    document.body.style.overflow = '';
    detailOpen = false;
    currentPhotoPart = null;
  }

  function addField(dl, label, value) {
    var row = el('div');
    row.appendChild(el('dt', null, label));
    row.appendChild(el('dd', null, (value === undefined || value === null || value === '') ? '-' : value));
    dl.appendChild(row);
  }

  $('detailBack').addEventListener('click', function () {
    if (detailOpen) history.back(); else closeDetail();
  });
  window.addEventListener('popstate', function () {
    if (!$('zoomView').hidden) { $('zoomView').hidden = true; history.pushState({ detail: true }, ''); return; }
    if (detailOpen) closeDetail();
  });

  $('detailPhoto').addEventListener('click', function () {
    $('zoomImg').src = this.src;
    $('zoomView').hidden = false;
  });
  $('zoomView').addEventListener('click', function () { this.hidden = true; });

  // ================= Price (รหัสผ่านแยก) =================

  /** เช็คว่ามีไฟล์ราคาบนเว็บไหม แล้วลองปลดล็อกด้วยกุญแจที่จำไว้ */
  function initPrice() {
    return fetch(PRICE_KEY_URL, { cache: 'no-store' }).then(function (r) {
      $('priceBtn').hidden = !r.ok;
      if (!r.ok) { forgetPrice(); return; }
      var saved = null;
      try { saved = localStorage.getItem(REMEMBER_PRICE); } catch (e) { }
      if (!saved || state.priceKeys) return;
      return importPairFull(b64ToBytes(saved)).then(function (k) {
        state.priceKeys = k;
        return loadPrices(true);
      }).catch(function () { forgetPrice(); });
    }).catch(function () { });
  }

  function loadPrices(force) {
    return fetch(PRICE_URL, { cache: 'no-cache' }).then(function (r) {
      if (!r.ok) throw new Error('noprice');
      return r.arrayBuffer();
    }).then(function (buf) {
      var bytes = new Uint8Array(buf);
      var fp = toHex(bytes.slice(bytes.length - 8));
      if (!force && fp === state.priceFingerprint) return false;
      return decryptFile(buf, state.priceKeys).then(gunzipToText).then(function (text) {
        var data = JSON.parse(text);
        state.prices = data.items || {};
        state.priceRate = data.rate || 30;
        state.upload = data.upload || null;
        buildIndex();
        if (currentItem && !$('detailView').hidden) updatePhotoActions(currentItem);
        state.priceFingerprint = fp;
        updatePriceButton();
        rerenderKeepScroll();
        return true;
      });
    }).catch(function (e) {
      if (e && e.message === 'badkey') {
        forgetPrice();
        toast('รหัสผู้ดูแลถูกเปลี่ยน กรุณาใส่ใหม่');
      }
      throw e;
    });
  }

  function forgetPrice() {
    state.priceKeys = null;
    state.prices = null;
    state.upload = null;
    buildIndex();
    if (currentItem) updatePhotoActions(currentItem);
    state.priceFingerprint = null;
    try { localStorage.removeItem(REMEMBER_PRICE); } catch (e) { }
    updatePriceButton();
  }

  function updatePriceButton() {
    $('priceBtn').textContent = state.prices ? '🔓 ผู้ดูแล' : '🔒 ผู้ดูแล';
  }

  /** ค้นหาด้วย Vendor ได้เฉพาะตอนปลดล็อกผู้ดูแล */
  function buildIndex() {
    for (var i = 0; i < state.items.length; i++) {
      var it = state.items[i];
      var v = vendorOf(it);
      it._idx = v ? it._base + ' ' + v.toUpperCase() : it._base;
    }
  }

  function vendorOf(it) {
    var pr = priceOf(it);
    return pr && pr[2] ? pr[2] : '';
  }

  function hasPrice(pr) {
    return pr && (pr[0] > 0 || pr[1]);
  }

  function rerenderKeepScroll() {
    var y = window.scrollY;
    var shown = state.shown;
    $('list').textContent = '';
    state.shown = 0;
    while (state.shown < Math.max(shown, PAGE_SIZE) && state.shown < state.filtered.length) renderMore();
    window.scrollTo(0, y);
  }

  function priceOf(it) {
    if (!state.prices) return null;
    return state.prices[it.p + '|' + it.a] || null;
  }

  function formatPrice(pr, withThb) {
    var txt = Number(pr[0]).toLocaleString(undefined, { maximumFractionDigits: 3 }) + (pr[1] ? ' ' + pr[1] : '');
    if (withThb && pr[1] === 'US') txt += ' (≈ ' + formatThb(pr) + ')';
    return txt;
  }

  function formatThb(pr) {
    var thb = pr[1] === 'US' ? pr[0] * state.priceRate : pr[0];
    return thb.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' ฿';
  }

  $('priceBtn').addEventListener('click', function () {
    if (state.prices) {
      if (confirm('ออกจากระดับผู้ดูแล และลืมรหัสผู้ดูแลในเครื่องนี้?')) {
        forgetPrice();
        applyFilter();
      }
      return;
    }
    $('pricePassword').value = '';
    $('priceError').hidden = true;
    $('priceView').hidden = false;
    setTimeout(function () { $('pricePassword').focus(); }, 50);
  });

  $('priceCancel').addEventListener('click', function () { $('priceView').hidden = true; });

  $('priceForm').addEventListener('submit', function (e) {
    e.preventDefault();
    var btn = $('priceUnlockBtn');
    var err = $('priceError');
    btn.disabled = true;
    btn.textContent = 'กำลังตรวจสอบ ...';
    err.hidden = true;
    var raw = null;
    unlockWithPassword($('pricePassword').value, PRICE_KEY_URL).then(function (master) {
      raw = master;
      return importPairFull(master);
    }).then(function (k) {
      state.priceKeys = k;
      return loadPrices(true);
    }).then(function () {
      if ($('priceRemember').checked && raw) {
        try { localStorage.setItem(REMEMBER_PRICE, bytesToB64(raw)); } catch (x) { }
      }
      $('priceView').hidden = true;
      toast('ปลดล็อกผู้ดูแลแล้ว');
    }).catch(function (x) {
      var m = x && x.message;
      state.priceKeys = null;
      err.textContent = m === 'badkey' ? 'รหัสผ่านผู้ดูแลไม่ถูกต้อง' : 'โหลดข้อมูลผู้ดูแลไม่สำเร็จ';
      err.hidden = false;
    }).then(function () {
      btn.disabled = false;
      btn.textContent = 'ปลดล็อกราคา';
    });
  });

  // ================= ถ่ายรูปส่งเข้า Server (ผู้ดูแล) =================

  var MAX_PHOTO_SIDE = 1600;

  function updatePhotoActions(it) {
    var box = $('photoActions');
    if (!state.upload || !state.priceKeys) { box.hidden = true; return; }
    box.hidden = false;
    $('takePhotoBtn').textContent = it.ph ? '📷 ถ่ายรูปใหม่ (แทนรูปเดิม)' : '📷 ถ่ายรูป';
    $('takePhotoBtn').disabled = false;
    setPhotoStatus('', '');
  }

  function setPhotoStatus(text, cls) {
    var p = $('photoStatus');
    p.textContent = text;
    p.className = 'photo-status' + (cls ? ' ' + cls : '');
    p.hidden = !text;
  }

  $('takePhotoBtn').addEventListener('click', function () {
    if (!currentItem) return;
    if (currentItem.ph && !confirm('ถ่ายรูปใหม่แทนรูปเดิมของ ' + currentItem.p + ' ?\n(รูปเดิมจะถูกเก็บไว้ใน _backup)')) return;
    $('photoInput').value = '';
    $('photoInput').click();
  });

  $('photoInput').addEventListener('change', function () {
    var file = this.files && this.files[0];
    var it = currentItem;
    if (!file || !it) return;
    var btn = $('takePhotoBtn');
    btn.disabled = true;
    setPhotoStatus('กำลังย่อรูป ...', '');
    resizeToJpeg(file).then(function (jpg) {
      setPhotoStatus('กำลังส่งรูป (' + Math.round(jpg.length / 1024) + ' KB) ...', '');
      return sendPhoto(it, jpg);
    }).then(function () {
      setPhotoStatus('✔ ส่งแล้ว — รูปจะเข้า Server ภายใน ~5 นาที และขึ้นเว็บหลังจากนั้นอีกไม่กี่นาที', 'ok');
    }).catch(function (e) {
      setPhotoStatus('✘ ส่งไม่สำเร็จ: ' + (e && e.message ? e.message : e), 'err');
    }).then(function () { btn.disabled = false; });
  });

  /** ย่อรูปจากกล้องให้ด้านยาวไม่เกิน 1600px แล้วแปลงเป็น JPEG */
  function resizeToJpeg(file) {
    return new Promise(function (resolve, reject) {
      var url = URL.createObjectURL(file);
      var img = new Image();
      img.onload = function () {
        var w = img.naturalWidth, h = img.naturalHeight;
        var scale = Math.min(1, MAX_PHOTO_SIDE / Math.max(w, h));
        var canvas = document.createElement('canvas');
        canvas.width = Math.round(w * scale);
        canvas.height = Math.round(h * scale);
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = '#fff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        URL.revokeObjectURL(url);
        canvas.toBlob(function (blob) {
          if (!blob) { reject(new Error('แปลงรูปไม่ได้')); return; }
          blob.arrayBuffer().then(function (b) { resolve(new Uint8Array(b)); }, reject);
        }, 'image/jpeg', 0.85);
      };
      img.onerror = function () { URL.revokeObjectURL(url); reject(new Error('เปิดรูปไม่ได้')); };
      img.src = url;
    });
  }

  /** payload = [ความยาว header 4 bytes] [header JSON] [JPEG] -> เข้ารหัส -> ส่งเข้า branch inbox */
  function sendPhoto(it, jpg) {
    var header = new TextEncoder().encode(JSON.stringify({
      part: it.p, area: it.a, by: 'ผู้ดูแล (มือถือ)', at: new Date().toISOString()
    }));
    var payload = new Uint8Array(4 + header.length + jpg.length);
    payload[0] = (header.length >>> 24) & 255;
    payload[1] = (header.length >>> 16) & 255;
    payload[2] = (header.length >>> 8) & 255;
    payload[3] = header.length & 255;
    payload.set(header, 4);
    payload.set(jpg, 4 + header.length);

    return encryptFile(payload, state.priceKeys).then(function (enc) {
      var up = state.upload;
      var name = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14) + '_' +
        toHex(window.crypto.getRandomValues(new Uint8Array(4)));
      var url = (up.api || GITHUB_API) + '/repos/' + encodeURIComponent(up.owner) + '/' +
        encodeURIComponent(up.repo) + '/contents/inbox/' + name + '.enc';
      return fetch(url, {
        method: 'PUT',
        headers: {
          'Authorization': 'Bearer ' + up.token,
          'Accept': 'application/vnd.github+json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message: 'Photo ' + it.p, content: bytesToB64(enc), branch: up.branch || 'inbox' })
      });
    }).then(function (r) {
      if (r.status === 201 || r.status === 200) return;
      return r.text().then(function (t) {
        var msg = 'GitHub ' + r.status;
        try { msg += ' ' + JSON.parse(t).message; } catch (x) { }
        if (r.status === 404) msg += ' (ยังไม่มี branch inbox — รอโปรแกรมสร้างให้ภายใน 5 นาที)';
        throw new Error(msg);
      });
    });
  }

  // ================= Utils =================

  function formatQty(q) {
    if (q === undefined || q === null) return '-';
    return Number(q).toLocaleString(undefined, { maximumFractionDigits: 3 });
  }

  function formatDate(s) {
    var m = /^(\d{4})-(\d{2})-(\d{2})/.exec(s || '');
    return m ? m[3] + '/' + m[2] + '/' + m[1] : s;
  }

  function formatDateTime(s) {
    var m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}:\d{2})/.exec(s || '');
    return m ? m[3] + '/' + m[2] + '/' + m[1] + ' ' + m[4] + ' น.' : s;
  }

  var toastTimer = null;
  function toast(msg) {
    var t = $('toast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 2500);
  }

  start();
})();
