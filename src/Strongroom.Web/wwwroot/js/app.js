// Strongroom UI. All data comes from the encrypted vault API; decrypted values live only in memory here
// and are discarded when the vault locks.
(() => {
  const $ = (id) => document.getElementById(id);
  const el = (tag, props = {}, ...kids) => {
    const n = Object.assign(document.createElement(tag), props);
    kids.forEach((k) => n.append(k));
    return n;
  };

  let items = [];
  let category = 'All items';
  let query = '';
  let selectedId = null;
  let editingId = null;
  let clipboardTimer = null;
  let registerMode = false;

  const colors = ['#6366f1', '#0ea5e9', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#14b8a6'];
  const colorFor = (s) => colors[[...s].reduce((a, c) => a + c.charCodeAt(0), 0) % colors.length];

  // ---------- API ----------
  class LockedError extends Error {}

  async function api(method, path, body) {
    const res = await fetch(`/api${path}`, {
      method,
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Strongroom': '1' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = res.status === 204 ? null : await res.json().catch(() => null);
    if (res.status === 401 && (path.startsWith('/credentials') || path.startsWith('/account'))) throw new LockedError('Your session expired. Please unlock again.');
    if (!res.ok) throw new Error(data?.error ?? `Request failed (${res.status})`);
    return data;
  }

  const fromApi = (c) => ({ id: c.id, name: c.name, url: c.url, user: c.username, pass: c.password, category: c.category, notes: c.notes });
  const toApi = (d) => ({ name: d.name, url: d.url, username: d.user, password: d.pass, category: d.category, notes: d.notes });

  // Runs an API action; on an expired session returns to the login screen.
  async function guarded(action) {
    try {
      return await action();
    } catch (err) {
      if (err instanceof LockedError) showLogin(err.message);
      else toast(err.message);
      return undefined;
    }
  }

  // ---------- helpers ----------
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg; t.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 2600);
  }

  async function copy(text, label) {
    try { await navigator.clipboard.writeText(text); } catch { /* clipboard unavailable */ }
    toast(`${label} copied — clears in 30s`);
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(() => navigator.clipboard?.writeText('').catch(() => {}), 30000);
  }

  function generatePassword(len = 20) {
    const set = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+';
    // Rejection sampling avoids modulo bias.
    const limit = 256 - (256 % set.length);
    let out = '';
    while (out.length < len) {
      const buf = new Uint8Array(len * 2);
      crypto.getRandomValues(buf);
      for (const b of buf) { if (b < limit && out.length < len) out += set[b % set.length]; }
    }
    return out;
  }

  function strength(pw) {
    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (pw.length >= 16) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    return Math.min(score, 5);
  }

  // ---------- rendering ----------
  function categories() {
    const counts = {};
    items.forEach((i) => (counts[i.category] = (counts[i.category] || 0) + 1));
    return [['All items', items.length], ...Object.entries(counts).sort(([a], [b]) => a.localeCompare(b))];
  }

  function renderNav() {
    if (category !== 'All items' && !items.some((i) => i.category === category)) category = 'All items';
    $('categoryNav').replaceChildren(...categories().map(([name, count]) => {
      const b = el('button', { className: name === category ? 'active' : '' }, el('span', { textContent: name }), el('span', { className: 'count', textContent: count }));
      b.onclick = () => { category = name; render(); };
      return b;
    }));
  }

  function visibleItems() {
    const q = query.trim().toLowerCase();
    return items
      .filter((i) => category === 'All items' || i.category === category)
      .filter((i) => !q || [i.name, i.user, i.url].some((v) => v.toLowerCase().includes(q)))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  function renderList() {
    const list = visibleItems();
    $('listTitle').textContent = category;
    $('listCount').textContent = `${list.length} item${list.length === 1 ? '' : 's'}`;
    $('empty').hidden = list.length > 0;
    $('items').replaceChildren(...list.map((i) => {
      const actions = el('div', { className: 'item-actions' });
      const u = el('button', { className: 'icon-btn', title: 'Copy username', textContent: '👤' });
      const p = el('button', { className: 'icon-btn', title: 'Copy password', textContent: '🔑' });
      u.onclick = (e) => { e.stopPropagation(); copy(i.user, 'Username'); };
      p.onclick = (e) => { e.stopPropagation(); copy(i.pass, 'Password'); };
      actions.append(u, p);
      const li = el('li', { className: 'item' + (i.id === selectedId ? ' selected' : '') },
        el('div', { className: 'avatar', textContent: i.name[0].toUpperCase(), style: `background:${colorFor(i.name)}` }),
        el('div', { className: 'item-text' }, el('strong', { textContent: i.name }), el('div', { textContent: i.user || i.url })),
        actions);
      li.onclick = () => { selectedId = i.id; render(); };
      return li;
    }));
  }

  function renderDetail() {
    const d = $('detail');
    const item = items.find((i) => i.id === selectedId);
    $('app').classList.toggle('has-detail', !!item);
    d.hidden = !item;
    if (!item) return;

    const row = (label, value, { secret = false, copyable = true, mono = false } = {}) => {
      if (!value) return '';
      const span = el('span', { textContent: secret ? '•'.repeat(12) : value, className: mono ? 'mono' : '' });
      const val = el('div', { className: 'val' }, span);
      if (secret) {
        const eye = el('button', { className: 'icon-btn', title: 'Reveal', textContent: '👁' });
        let shown = false;
        eye.onclick = () => { shown = !shown; span.textContent = shown ? value : '•'.repeat(12); };
        val.append(eye);
      }
      if (copyable) {
        const c = el('button', { className: 'icon-btn', title: 'Copy', textContent: '📋' });
        c.onclick = () => copy(value, label);
        val.append(c);
      }
      return el('div', { className: 'row' }, el('label', { textContent: label }), val);
    };

    const close = el('button', { className: 'icon-btn', title: 'Close', textContent: '✕' });
    close.onclick = () => { selectedId = null; render(); };
    const edit = el('button', { className: 'btn wide', textContent: 'Edit' });
    edit.onclick = () => openDialog(item);

    d.replaceChildren(
      el('div', { className: 'detail-head' },
        el('div', { className: 'avatar', textContent: item.name[0].toUpperCase(), style: `background:${colorFor(item.name)}` }),
        el('div', { style: 'flex:1;min-width:0' }, el('h2', { textContent: item.name }), el('span', { className: 'muted', textContent: item.category })),
        close),
      row('Username', item.user),
      row('Password', item.pass, { secret: true, mono: true }),
      row('Website', item.url),
      row('Notes', item.notes, { copyable: false }),
      el('div', { className: 'detail-actions' }, edit));
  }

  function render() { renderNav(); renderList(); renderDetail(); }

  // ---------- dialog ----------
  function updateStrength() {
    const s = strength($('fPass').value);
    const bar = $('strengthBar');
    bar.style.width = `${(s / 5) * 100}%`;
    bar.style.background = s <= 2 ? 'var(--danger)' : s <= 3 ? 'var(--warn)' : 'var(--good)';
    $('strengthText').textContent = $('fPass').value ? ['Very weak', 'Weak', 'Weak', 'Fair', 'Good', 'Strong'][s] : '';
  }

  function openDialog(item) {
    editingId = item?.id ?? null;
    $('dialogTitle').textContent = item ? 'Edit credential' : 'Add credential';
    $('fName').value = item?.name ?? '';
    $('fUrl').value = item?.url ?? '';
    $('fUser').value = item?.user ?? '';
    const cat = item?.category ?? (category === 'All items' ? 'Work apps' : category);
    const select = $('fCategory');
    if (![...select.options].some((o) => o.value === cat)) select.append(new Option(cat, cat));
    select.value = cat;
    $('fPass').value = item?.pass ?? '';
    $('fPass').type = 'password';
    $('fNotes').value = item?.notes ?? '';
    $('deleteBtn').hidden = !item;
    updateStrength();
    $('editDialog').showModal();
  }

  function closeDialog() {
    $('editForm').reset();
    $('fPass').value = '';
    $('editDialog').close();
  }

  $('addBtn').onclick = () => openDialog(null);
  $('cancelBtn').onclick = closeDialog;
  $('editDialog').addEventListener('cancel', () => { $('fPass').value = ''; });
  $('fPass').oninput = updateStrength;
  $('genBtn').onclick = () => { $('fPass').value = generatePassword(); $('fPass').type = 'text'; updateStrength(); };

  $('editForm').onsubmit = async (e) => {
    e.preventDefault();
    const data = {
      name: $('fName').value.trim(), url: $('fUrl').value.trim(), user: $('fUser').value.trim(),
      category: $('fCategory').value, pass: $('fPass').value, notes: $('fNotes').value.trim(),
    };
    const saved = await guarded(() => editingId
      ? api('PUT', `/credentials/${editingId}`, toApi(data))
      : api('POST', '/credentials', toApi(data)));
    if (!saved) return;

    const item = fromApi(saved);
    const idx = items.findIndex((i) => i.id === item.id);
    if (idx >= 0) items[idx] = item; else items.push(item);
    selectedId = item.id;
    toast(editingId ? 'Credential updated' : 'Credential added');
    closeDialog();
    render();
  };

  $('deleteBtn').onclick = async () => {
    if (!confirm('Delete this credential? This cannot be undone.')) return;
    const id = editingId;
    const ok = await guarded(async () => { await api('DELETE', `/credentials/${id}`); return true; });
    if (!ok) return;
    items = items.filter((i) => i.id !== id);
    if (selectedId === id) selectedId = null;
    closeDialog(); render(); toast('Credential deleted');
  };

  // ---------- login / register / lock ----------
  document.querySelectorAll('[data-toggle]').forEach((b) => {
    b.onclick = () => { const i = $(b.dataset.toggle); i.type = i.type === 'password' ? 'text' : 'password'; };
  });

  function setMode(register) {
    registerMode = register;
    $('confirmField').hidden = !register;
    $('confirmPassword').required = register;
    $('loginSubmit').textContent = register ? 'Create account' : 'Unlock';
    $('modeToggle').textContent = register ? 'I already have an account' : 'Create a new account';
    $('loginSubtitle').textContent = register
      ? 'Choose a username and a strong master password.'
      : 'Enter your master password to unlock your vault.';
    $('masterPassword').autocomplete = register ? 'new-password' : 'current-password';
    showError('');
  }
  $('modeToggle').onclick = () => setMode(!registerMode);

  function showError(msg) {
    $('loginError').textContent = msg;
    $('loginError').hidden = !msg;
  }

  function showLogin(message = '') {
    items = []; selectedId = null; query = ''; category = 'All items';
    $('search').value = '';
    document.querySelectorAll('dialog[open]').forEach((d) => d.close());
    $('editForm').reset(); $('pwForm').reset(); $('fPass').value = '';
    render(); // wipes decrypted entries from the page, not just from memory
    $('detail').replaceChildren();
    $('app').hidden = true; $('login').hidden = false;
    $('masterPassword').value = ''; $('confirmPassword').value = '';
    setMode(false);
    showError(message);
    ($('loginUser').value ? $('masterPassword') : $('loginUser')).focus();
  }

  async function enterApp() {
    const list = await api('GET', '/credentials/');
    items = list.map(fromApi);
    $('login').hidden = true; $('app').hidden = false;
    $('masterPassword').value = ''; $('confirmPassword').value = '';
    showError('');
    render();
  }

  $('loginForm').onsubmit = async (e) => {
    e.preventDefault();
    showError('');
    const username = $('loginUser').value.trim();
    const password = $('masterPassword').value;
    if (registerMode && password !== $('confirmPassword').value) return showError('The passwords do not match.');

    const btn = $('loginSubmit');
    btn.disabled = true;
    try {
      await api('POST', registerMode ? '/register' : '/login', { username, password });
      await enterApp();
    } catch (err) {
      showError(err.message);
    } finally {
      btn.disabled = false;
    }
  };

  // ---------- change master password ----------
  function closePwDialog() {
    $('pwForm').reset();
    $('pwError').hidden = true;
    $('pwDialog').close();
  }
  $('changePwBtn').onclick = () => { $('pwForm').reset(); $('pwError').hidden = true; $('pwDialog').showModal(); };
  $('pwCancel').onclick = closePwDialog;
  $('pwDialog').addEventListener('cancel', () => $('pwForm').reset());

  $('pwForm').onsubmit = async (e) => {
    e.preventDefault();
    const fail = (m) => { $('pwError').textContent = m; $('pwError').hidden = false; };
    $('pwError').hidden = true;
    if ($('pwNew').value !== $('pwConfirm').value) return fail('The new passwords do not match.');

    const btn = $('pwSubmit');
    btn.disabled = true;
    try {
      await api('POST', '/account/change-password', { currentPassword: $('pwCurrent').value, newPassword: $('pwNew').value });
      closePwDialog();
      toast('Master password changed');
    } catch (err) {
      if (err instanceof LockedError) { closePwDialog(); showLogin(err.message); }
      else fail(err.message);
    } finally {
      btn.disabled = false;
    }
  };

  async function lock() {
    try { await api('POST', '/logout'); } catch { /* server unreachable: still clear the screen */ }
    showLogin();
  }
  $('lockBtn').onclick = lock;

  let idle;
  const resetIdle = () => { clearTimeout(idle); idle = setTimeout(() => { if (!$('app').hidden) lock(); }, 5 * 60 * 1000); };
  ['mousemove', 'keydown', 'click'].forEach((ev) => document.addEventListener(ev, resetIdle));
  resetIdle();

  $('search').oninput = (e) => { query = e.target.value; renderList(); };

  $('themeBtn').onclick = () => {
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
  };

  // ---------- start ----------
  (async () => {
    try {
      const status = await api('GET', '/status');
      if (status.unlocked) { await enterApp(); return; }
    } catch { /* fall through to login */ }
    showLogin();
  })();
})();
