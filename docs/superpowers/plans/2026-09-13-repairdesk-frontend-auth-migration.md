# RepairDesk Frontend Auth Migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewire the RepairDesk static single-file app (`D:\v2.html`) so login, signup, password reset, session validation, and the admin Users panel talk to the Supabase backend instead of `localStorage`, while keeping all shop data (customers, receipts, settings) local exactly as today.

**Architecture:** The front-end keeps its current look, i18n, and localStorage shop layer. A new `RD_API` module wraps fetch calls to the deployed Edge Functions. `rd_sess` holds the opaque session token instead of a uid. `authUser` is hydrated by `/validate-session`. The admin Users view (`renderUsersView`) becomes a read-only+actions panel driven by the admin endpoints. On migration re-register, once the backend returns a new uid, the app re-prefixes the user's existing shop-data keys from the old local uid to the new uid so no shop data is orphaned.

**Tech Stack:** Vanilla JS (single `index.html`), Web Crypto SHA-256 (already present) for backend-verifiable hashing, fetch to Supabase Edge Functions. No new libraries, no build step. Deployment stays: edit `D:\v2.html` → copy to `D:\Default Project\index.html` → Commit & push → GitHub Pages.

**Spec:** `docs/superpowers/specs/2026-09-13-repairdesk-auth-backend-design.md`
**Backend plan (already written):** `docs/superpowers/plans/2026-09-13-repairdesk-auth-backend.md` — this frontend plan assumes those endpoints are deployed and working.

## Global Constraints

- **Secrets:** The service-role key never appears in the front-end. Only the public anon key + project URL are embedded here (they are public by design in a static site; all real authorization happens server-side behind RLS + Edge Functions).
- **Existing behavior preserved:** admin login `akuma/gouki` must still trigger `playAkumaFx()` and reach the admin panel; per-receipt prices, earnings blur, activity logging, and all shop views must be untouched.
- **i18n parity:** every new user-facing string needs an `en`, `fr`, AND `ar` entry (three dicts stay identical in key count). French strings escape apostrophes as `\'`.
- **Hashing stays local for outbound calls:** the login/signup flow DOES NOT hash client-side for the backend (the Edge Functions verify). But the admin seed relies on backend-known SHA-256; the front-end keeps its own `hashPassword` for the legacy fallback path only if it ever loads pre-backend accounts — in this new version, remove reliance on local account entries.
- **`rd_sess` semantic change:** value becomes the session token (was the uid). Any code reading `Store.getSession()` expecting a uid must change.
- **Auth gating:** all non-auth API calls resolve the caller from the token server-side; the front-end only decides UI (show/hide admin nav) from `authUser.role`.

---

## File Structure

```
Modify ONLY: D:\v2.html   (canonical; single HTML file contains script)
Deploy copy: D:\Default Project\index.html  (git copy of D:\v2.html, pushed to Pages)
```

Plan tasks reference the current `D:\v2.html` line numbers from `4ab091c` (tag `pre-backend-4ab091c`); line numbers may drift as edits land — always locate by surrounding anchors, not absolute line numbers.

---

### Task 1: API client module (`RD_API`) + config

**Files:**
- Modify: `D:\v2.html` — insert a new block right after the `Store` object closes (currently ends at L1386, after `_clearSession`), before the shop-data helpers.
- Test: `node --check` on the extracted script block.

**Interfaces:**
- Consumes: (front-end base, no external deps)
- Produces:
  - `const RD_CONFIG = { projectUrl, anonKey, functionBase, allowedOrigin }`
  - `async function rdFetch(path, {method, body, token})` → parses JSON, throws `RDError` with `{errorCode, status}` on non-2xx, returns parsed body
  - `const RD = { login, signup, reset, validateSession, logout, adminListAccounts, adminLoginHistory, adminBan, adminIssueCode, adminListSessions }`

- [ ] **Step 1: Write the config + client block**

Insert into `D:\v2.html` after the `Store` object definition (after the closing `};` of `Store`):

```js
/* ===================================================================
   RD_API — Supabase backend client
   =================================================================== */
const RD_CONFIG = {
  projectUrl: 'https://<project-ref>.supabase.co',
  anonKey: '<anon-key>',
  allowedOrigin: 'https://kossaitaguine331.github.io'
};
const RD = (() => {
  const base = RD_CONFIG.projectUrl + '/functions/v1';

  async function rdFetch(path, opts = {}) {
    const { method = 'GET', body, token } = opts;
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    let res;
    try {
      res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    } catch (netErr) {
      throw new RDError('network_error', 0);
    }
    let json = null;
    try { json = await res.json(); } catch (e) { /* body may be empty */ }
    if (!res.ok || (json && json.error)) {
      throw new RDError((json && json.error) || 'server_error', res.status);
    }
    return json;
  }

  class RDError extends Error {
    constructor(errorCode, status) { super(errorCode); this.errorCode = errorCode; this.status = status; }
  }

  const login = (email, password) => rdFetch('/login', { method: 'POST', body: { email, password } });
  const signup = (email, name, password, confirmPassword, code) =>
    rdFetch('/signup', { method: 'POST', body: { email, name, password, confirmPassword, code } });
  const reset = (email, code, newPassword, confirmPassword) =>
    rdFetch('/reset', { method: 'POST', body: { email, code, newPassword, confirmPassword } });
  const validateSession = (token) => rdFetch('/validate-session', { method: 'POST', body: { token } });
  const logout = (token) => rdFetch('/logout', { method: 'POST', body: { token } });
  const adminListAccounts = (token) => rdFetch('/list-accounts', { method: 'GET', token });
  const adminLoginHistory = (token, uid) => rdFetch('/login-history?uid=' + encodeURIComponent(uid), { method: 'GET', token });
  const adminBan = (token, uid, banned) => rdFetch('/ban', { method: 'POST', token, body: { uid, banned } });
  const adminIssueCode = (token, email, note) => rdFetch('/issue-code', { method: 'POST', token, body: { email, note } });
  const adminListSessions = (token, uid) => rdFetch('/list-sessions?uid=' + encodeURIComponent(uid), { method: 'GET', token });

  return { RDError, login, signup, reset, validateSession, logout, adminListAccounts, adminLoginHistory, adminBan, adminIssueCode, adminListSessions };
})();
```

- [ ] **Step 2: Syntax-check the app**

Extract the `<script>` content and run node's syntax check:

```powershell
node -e "const fs=require('fs');const s=fs.readFileSync('D:/v2.html','utf8');const m=s.match(/<script>([\s\S]*?)<\/script>/);fs.writeFileSync('C:/Users/kossai/AppData/Local/Temp/opencode/v2check.js',m[1]);"
node --check "C:/Users/kossai/AppData/Local/Temp/opencode/v2check.js"
```

Expected: no output (pass). Note: `RD_CONFIG` must be filled with real project values later — placeholders now; Task 6 replaces them.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "Add RD_API fetch client and config for Supabase backend"
```

---

### Task 2: Session layer — store the token, validate on boot

**Files:**
- Modify: `D:\v2.html` — `Store` session helpers (L1384–1386); `bootstrapAfterLang` (L3477); `beginSession` (L3347); `handleSignout` (L3362).

**Interfaces:**
- Consumes: `RD.validateSession`, `RD.logout`.
- Produces: `beginSession(acc)` stores `rd_sess` = token; `authUser` holds account w/ uid+role; `getSession()` reads token; `bootstrapAfterLang()` becomes async and validates the token before entering the app.

- [ ] **Step 1: Repurpose `Store` session helpers**

Replace:

```js
  getSession(){ return this._readLocal('sess'); },
  _saveSession(uid){ this._writeLocal('sess', uid); },
  _clearSession(){ try{ localStorage.removeItem('rd_sess'); }catch(e){} },
```

with:

```js
  getSession(){ return this._readLocal('sess'); },          // now = opaque token
  _saveSession(token){ this._writeLocal('sess', token); },  // new param name only (same key)
  _clearSession(){ try{ localStorage.removeItem('rd_sess'); }catch(e){} },
```

- [ ] **Step 2: Rewrite `beginSession` to accept a backend account (token + identity), keep `authUser`**

Replace `beginSession` (L3347–3360) with:

```js
function beginSession(acc){
  authUser = { uid: acc.uid, email: acc.email, name: acc.name, role: acc.role };
  Store.account = acc.uid;
  if(acc.token) Store._saveSession(acc.token);
  const uBtn = document.getElementById('navUsersBtn');
  if(uBtn) uBtn.style.display = (authUser.role === 'admin') ? '' : 'none';
  hideAuthScreen();
  gotoTenantScreen();
  renderTenantScreen();
}
```

- [ ] **Step 3: Rewrite `bootstrapAfterLang` to validate the stored token**

Replace `bootstrapAfterLang` (L3477–3484) with:

```js
async function bootstrapAfterLang(){
  const token = Store.getSession();
  if(token){
    try{
      const v = await RD.validateSession(token);
      if(v && v.valid && v.uid){
        beginSession({ uid: v.uid, name: v.name, role: v.role, email: '', token });
        return;
      }
    }catch(e){}
    Store._clearSession();
  }
  showAuthScreen();
}
```

Note: `bootstrapAfterLang` is called from the `init` IIFE (L3511) and from each `.lang-opt` click handler (L3472). The click handler currently calls it synchronously — you must make those two call sites `await`/ignore the returned promise:

At L3472 (`.lang-opt` handler) change `bootstrapAfterLang();` to:
```js
bootstrapAfterLang();
```

(safe to leave as-is — a floating promise is fine for a user click).

At L3511 (`if(stored){ hideLangScreen(); bootstrapAfterLang(); }`) leave the call as-is too (async fire-and-forget is acceptable on boot).

- [ ] **Step 4: `handleSignout` calls the server logout and clears the token**

Replace `handleSignout` (L3362–3368) with:

```js
function handleSignout(){
  const token = Store.getSession();
  authUser = null;
  Store._clearSession();
  Store.account = null;
  try{ localStorage.removeItem('rd_activeTenant'); }catch(e){}
  if(token){ RD.logout(token).catch(() => {}); }   // best-effort server-side kill
  showAuthScreen();
}
```

- [ ] **Step 5: Syntax-check** (repeat Task 1 Step 2 standalone check).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Store opaque session token; validate on boot; server logout"
```

---

### Task 3: `authSubmit` — login/signup/reset through the API

**Files:**
- Modify: `D:\v2.html` — `authSubmit` (L3383–3456); `genAccessCode` stays (used only for admin issue-code? No — replaced in Task 5); `isApproved` (L3326) no longer needed for login gating.

**Interfaces:**
- Consumes: `RD.login`, `RD.signup`, `RD.reset`.
- Produces: async `authSubmit` handling three modes with API calls; error-code → i18n mapping function `authErr(code)`.

- [ ] **Step 1: Add the error-mapping helper** (insert just above `async function authSubmit`):

```js
function authErr(code){
  const map = {
    network_error: 'auth_network',
    auth_invalid: 'auth_invalid',
    banned: 'auth_banned',
    access_blocked: 'access_blocked',
    too_many_attempts: 'auth_too_many',
    auth_email_invalid: 'auth_email_invalid',
    auth_password_short: 'auth_password_short',
    auth_password_mismatch: 'auth_password_mismatch',
    auth_exists: 'auth_exists',
    full_name_required: 'full_name_required',
    access_code_invalid: 'access_code_invalid',
    reset_no_account: 'reset_no_account',
    reset_code_invalid: 'reset_code_invalid',
    server_error: 'auth_server',
    origin_not_allowed: 'auth_server'
  };
  return I18N.t(map[code] || 'auth_server');
}
```

- [ ] **Step 2: Rewrite `authSubmit`**

Replace the entire function body (L3383–3456) with:

```js
async function authSubmit(e){
  e.preventDefault();
  const email = document.getElementById('authEmail').value.trim().toLowerCase();
  const password = document.getElementById('authPassword').value;

  if(authMode.isReset){
    const confirmPw = document.getElementById('authConfirm').value;
    const code = document.getElementById('authCode').value.trim();
    if(password !== confirmPw){ authMsg(I18N.t('auth_password_mismatch')); return; }
    try{
      await RD.reset(email, code, password, confirmPw);
      authMsg(I18N.t('reset_success'), 'info');
      setAuthMode(false);
      return;
    }catch(err){
      authMsg(authErr(err.errorCode));
      return;
    }
  }

  if(authMode.isSignup){
    const name = document.getElementById('authName').value.trim();
    const confirmPw = document.getElementById('authConfirm').value;
    const code = document.getElementById('authCode').value.trim();
    if(password !== confirmPw){ authMsg(I18N.t('auth_password_mismatch')); return; }
    if(!name){ authMsg(I18N.t('full_name_required')); return; }
    try{
      const res = await RD.signup(email, name, password, confirmPw, code);
      beginSession({ uid: res.uid, email, name, role: res.role, token: res.token });
      migrateShopDataForEmail(email, res.uid);
      return;
    }catch(err){
      authMsg(authErr(err.errorCode));
      return;
    }
  }

  /* login */
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email !== 'akuma'){ authMsg(I18N.t('auth_email_invalid')); return; }
  if(password.length < 6 && email !== 'akuma'){ authMsg(I18N.t('auth_password_short')); return; }
  try{
    const res = await RD.login(email, password);
    if(email === 'akuma') playAkumaFx();
    beginSession({ uid: res.uid, email, name: res.name, role: res.role, token: res.token });
    migrateShopDataForEmail(email, res.uid);
  }catch(err){
    authMsg(authErr(err.errorCode));
  }
}
```

- [ ] **Step 3: Add `migrateShopDataForEmail(email, newUid)`** (insert after `authSubmit`):

```js
/* Re-prefix a legacy local account's shop keys from its old uid to the new
   backend uid so the returning client keeps all tenant data. */
function migrateShopDataForEmail(email, newUid){
  try{
    const accts = Store._accounts() || [];
    const legacy = accts.find(a => a.email === email && a.role !== 'admin');
    if(!legacy || legacy.uid === newUid) return;
    const oldPrefix = 'rd_' + legacy.uid + '_';
    const newPrefix = 'rd_' + newUid + '_';
    const keys = [];
    for(let i = 0; i < localStorage.length; i++){
      const k = localStorage.key(i);
      if(k && k.indexOf(oldPrefix) === 0) keys.push(k);
    }
    keys.forEach(k => {
      const v = localStorage.getItem(k);
      if(v !== null){ localStorage.setItem(newPrefix + k.slice(oldPrefix.length), v); localStorage.removeItem(k); }
    });
    /* drop the legacy account entry so we never re-run the migration */
    localStorage.setItem('rd_accts', JSON.stringify(accts.filter(a => a.uid !== legacy.uid)));
  }catch(e){ /* migration is best-effort; never block auth */ }
}
```

- [ ] **Step 4: Syntax-check** (repeat Step tool).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Route auth through backend API; migrate local shop keys to new uid"
```

---

### Task 4: i18n — add the new strings in all three languages

**Files:**
- Modify: `D:\v2.html` — the three dicts inside `I18N.dict` (en block, fr block, ar block; each currently ~256 keys).

**Interfaces:**
- Consumes: existing `I18N.t`.
- Produces: new keys present in ALL THREE dicts: `auth_network`, `auth_banned`, `auth_too_many`, `auth_server`, `users_banned`, `users_unban`, `users_ban`, `users_login_history`, `users_sessions`, `users_last_login`, `users_reported_ip`, `users_device`, `users_attempt_time`, `users_loading`, `users_code_reused`.

- [ ] **Step 1: Add the keys to the `en` dict**

Inside the `en:` block of `I18N.dict`, add (keys must match the other two dicts exactly):

```js
auth_network: 'Cannot reach the server. Check your connection and try again.',
auth_banned: 'This account has been banned. Contact your administrator.',
auth_too_many: 'Too many attempts. Try again later.',
auth_server: 'Server error. Please try again.',
users_banned: 'Banned',
users_unban: 'Unban',
users_ban: 'Ban',
users_login_history: 'Login history',
users_sessions: 'Active sessions',
users_last_login: 'Last login',
users_reported_ip: 'Reported IP',
users_device: 'Device',
users_attempt_time: 'Attempt time',
users_loading: 'Loading…',
users_code_reused: 'A code already exists for this email (reused).',
```

- [ ] **Step 2: Add matching keys to `fr`**

```js
auth_network: 'Impossible de joindre le serveur. Vérifiez votre connexion.',
auth_banned: 'Ce compte a été banni. Contactez votre administrateur.',
auth_too_many: 'Trop de tentatives. Réessayez plus tard.',
auth_server: 'Erreur serveur. Veuillez réessayer.',
users_banned: 'Banni',
users_unban: 'Débannir',
users_ban: 'Bannir',
users_login_history: 'Historique de connexion',
users_sessions: 'Sessions actives',
users_last_login: 'Dernière connexion',
users_reported_ip: 'IP rapportée',
users_device: 'Appareil',
users_attempt_time: 'Date de tentative',
users_loading: 'Chargement…',
users_code_reused: 'Un code existe déjà pour cet email (réutilisé).',
```

- [ ] **Step 3: Add matching keys to `ar`**

```js
auth_network: 'تعذر الوصول إلى الخادم. تحقق من اتصالك.',
auth_banned: 'تم حظر هذا الحساب. اتصل بمسؤولك.',
auth_too_many: 'محاولات كثيرة جدًا. حاول مرة أخرى لاحقًا.',
auth_server: 'خطأ في الخادم. حاول مرة أخرى.',
users_banned: 'محظور',
users_unban: 'إلغاء الحظر',
users_ban: 'حظر',
users_login_history: 'سجل الدخول',
users_sessions: 'الجلسات النشطة',
users_last_login: 'آخر دخول',
users_reported_ip: 'IP المُبلَّغ',
users_device: 'الجهاز',
users_attempt_time: 'وقت المحاولة',
users_loading: 'جارٍ التحميل…',
users_code_reused: 'يوجد رمز لهذا البريد بالفعل (أُعيد استخدامه).',
```

- [ ] **Step 4: Verify key-count parity across the three dicts**

```powershell
node -e "const fs=require('fs');const s=fs.readFileSync('D:/v2.html','utf8');const m=s.match(/dict:\s*\{\s*en:\{([\s\S]*?)\},\s*fr:\{([\s\S]*?)\},\s*ar:\{([\s\S]*?)\}\s*\}/);const c=t=>(t.match(/^[a-z_]+:/gm)||[]).length;console.log('en',c(m[1]),'fr',c(m[2]),'ar',c(m[3]));"
```

Expected: `en N fr N ar N` with all three N equal (comprehensive check: the new keys appear in all three).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add backend-aware i18n strings in en/fr/ar"
```

---

### Task 5: Admin Users view → API-backed accounts/logs/ban panel

**Files:**
- Modify: `D:\v2.html` — `renderUsersView` (L2989–3099) and the second call at L3066; `genAccessCode` (L3315) and `getRegistry`/`saveRegistry` (L3282–3308) become unused (keep or remove — see below); the `users` nav case at L1675 stays.

**Interfaces:**
- Consumes: `RD.adminListAccounts`, `RD.adminLoginHistory`, `RD.adminBan`, `RD.adminIssueCode`, `RD.adminListSessions`.
- Produces: async `renderUsersView(el)` showing: issue-code form (server-issued), accounts table (email, name, status, last login, Ban/Unban, "History" expand), login-history detail per account, active sessions per account.

- [ ] **Step 1: Replace `renderUsersView` with the API-backed version**

Replace L2989–L3099 (the whole function including the revoke/publish listeners) with:

```js
async function renderUsersView(el){
  if(!authUser || authUser.role !== 'admin'){
    el.innerHTML = '<div class="content-header"><h2>' + esc(I18N.t('nav_users')) + '</h2></div><p style="color:var(--muted);">' + esc(I18N.t('users_restricted')) + '</p>';
    return;
  }
  const token = Store.getSession();
  el.innerHTML = '<div class="content-header"><h2>' + esc(I18N.t('nav_users')) + '</h2></div>'
    + '<p style="color:var(--muted);">' + esc(I18N.t('users_loading')) + '</p>';

  let accounts = [];
  try{
    accounts = await RD.adminListAccounts(token) || [];
  }catch(e){ accounts = []; }

  let html = '<div class="content-header"><h2>' + esc(I18N.t('nav_users')) + '</h2></div>';
  html += '<p class="field-hint" style="margin-bottom:16px;">' + esc(I18N.t('users_hint')) + '</p>';

  /* Issue a code (server-side; idempotent per email) */
  html += '<div class="settings-section"><h3>' + esc(I18N.t('users_issue')) + '</h3>';
  html += '<div class="row" style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-start;">';
  html += '<div class="field" style="flex:1;min-width:180px;"><label>' + esc(I18N.t('email')) + '</label><input id="newUserEmail" placeholder="client@beemail.com"></div>';
  html += '<div class="field"><label>' + esc(I18N.t('users_note')) + '</label><input id="newUserNote" placeholder="' + esc(I18N.t('users_note_ph')) + '"></div>';
  html += '<div class="field" style="align-self:flex-end;"><label>&nbsp;</label><button class="btn primary" id="genUserCodeBtn">' + esc(I18N.t('users_gen')) + '</button></div>';
  html += '</div>';
  html += '<div id="genCodeResult" style="margin-top:10px;font-weight:700;color:var(--purple);"></div>';
  html += '</div>';

  /* Registered accounts with ban + history */
  html += '<div class="settings-section"><h3>' + esc(I18N.t('users_accounts')) + '</h3>';
  html += '<div class="table-wrap" style="overflow-x:auto;">';
  html += '<table class="rc-table" style="width:100%;border-collapse:collapse;font-size:13px;">';
  html += '<thead><tr><th style="text-align:left;padding:8px;">' + esc(I18N.t('email'))
    + '</th><th style="text-align:left;padding:8px;">' + esc(I18N.t('full_name'))
    + '</th><th style="text-align:left;padding:8px;">' + esc(I18N.t('users_last_login'))
    + '</th><th style="text-align:left;padding:8px;">' + esc(I18N.t('status'))
    + '</th><th style="padding:8px;"></th></tr></thead><tbody>';
  if(accounts.length === 0){
    html += '<tr><td colspan="5" style="padding:12px;color:var(--muted);">' + esc(I18N.t('users_no_accounts')) + '</td></tr>';
  }
  accounts.forEach(a => {
    const banned = !!a.banned; const approved = !!a.approved;
    const lastLogin = a.last_login ? new Date(a.last_login).toLocaleString() : '—';
    const statusHtml = banned
      ? '<span style="color:var(--danger);">' + esc(I18N.t('users_banned')) + '</span>'
      : (approved
        ? '<span style="color:var(--green-ink);">' + esc(I18N.t('users_active')) + '</span>'
        : '<span style="color:var(--danger);">' + esc(I18N.t('users_blocked')) + '</span>');
    html += '<tr>'
      + '<td style="padding:8px;">' + esc(a.email) + '</td>'
      + '<td style="padding:8px;">' + esc(a.name || '') + '</td>'
      + '<td style="padding:8px;">' + lastLogin + '</td>'
      + '<td style="padding:8px;">' + statusHtml + '</td>'
      + '<td style="padding:8px;text-align:right;white-space:nowrap;">'
      + '<button class="btn" data-history="' + esc(a.uid) + '" style="padding:5px 10px;font-size:12px;">' + esc(I18N.t('users_login_history')) + '</button> '
      + '<button class="btn ' + (banned ? '' : 'danger') + '" data-ban="' + esc(a.uid) + '" data-banned="' + (banned ? '1' : '0') + '" style="padding:5px 10px;font-size:12px;">' + (banned ? esc(I18N.t('users_unban')) : esc(I18N.t('users_ban'))) + '</button>'
      + '</td></tr>';
  });
  html += '</tbody></table></div></div>';

  /* Detail drawer (history + sessions), populated async on demand */
  html += '<div id="adminDetail" style="margin-top:16px;"></div>';

  el.innerHTML = html;

  document.getElementById('genUserCodeBtn').addEventListener('click', async () => {
    const email = document.getElementById('newUserEmail').value.trim().toLowerCase();
    const note = document.getElementById('newUserNote').value.trim();
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){ alert(I18N.t('auth_email_invalid')); return; }
    try{
      const res = await RD.adminIssueCode(token, email, note);
      document.getElementById('genCodeResult').textContent =
        (res.reused ? I18N.t('users_code_reused') + ' ' : '') + email + ' \u2192 ' + res.code;
    }catch(err){
      document.getElementById('genCodeResult').textContent = authErr(err.errorCode);
    }
  });

  el.querySelectorAll('[data-ban]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const uid = btn.getAttribute('data-ban');
      const banned = btn.getAttribute('data-banned') === '1';
      if(banned && !confirm(I18N.t('users_confirm_unban'))) return;
      if(!banned && !confirm(I18N.t('users_confirm_ban'))) return;
      try{
        await RD.adminBan(token, uid, !banned);
        renderUsersView(el);
      }catch(err){
        alert(authErr(err.errorCode));
      }
    });
  });

  el.querySelectorAll('[data-history]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const uid = btn.getAttribute('data-history');
      const detail = document.getElementById('adminDetail');
      if(!detail) return;
      detail.innerHTML = '<p style="color:var(--muted);">' + esc(I18N.t('users_loading')) + '</p>';
      try{
        const [history, sessions] = await Promise.all([
          RD.adminLoginHistory(token, uid),
          RD.adminListSessions(token, uid)
        ]);
        let h = '<div class="settings-section"><h3>' + esc(I18N.t('users_login_history')) + '</h3>';
        h += '<div class="table-wrap" style="overflow-x:auto;"><table class="rc-table" style="width:100%;border-collapse:collapse;font-size:12px;">';
        h += '<thead><tr><th style="text-align:left;padding:6px;">' + esc(I18N.t('users_attempt_time')) + '</th>'
          + '<th style="text-align:left;padding:6px;">' + esc(I18N.t('status')) + '</th>'
          + '<th style="text-align:left;padding:6px;">' + esc(I18N.t('users_reported_ip')) + '</th>'
          + '<th style="text-align:left;padding:6px;">' + esc(I18N.t('users_device')) + '</th></tr></thead><tbody>';
        (history || []).forEach(row => {
          h += '<tr><td style="padding:6px;">' + new Date(row.attempted_at).toLocaleString() + '</td>'
            + '<td style="padding:6px;">' + (row.success ? '<span style="color:var(--green-ink);">✓</span>' : '<span style="color:var(--danger);">✗</span>') + '</td>'
            + '<td style="padding:6px;font-family:monospace;">' + esc(row.ip || '—') + '</td>'
            + '<td style="padding:6px;">' + esc(row.device || '—') + '</td></tr>';
        });
        h += '</tbody></table></div></div>';

        h += '<div class="settings-section"><h3>' + esc(I18N.t('users_sessions')) + '</h3>';
        h += '<div class="table-wrap" style="overflow-x:auto;"><table class="rc-table" style="width:100%;border-collapse:collapse;font-size:12px;">';
        h += '<thead><tr><th style="text-align:left;padding:6px;">' + esc(I18N.t('users_device')) + '</th>'
          + '<th style="text-align:left;padding:6px;">' + esc(I18N.t('users_attempt_time')) + '</th></tr></thead><tbody>';
        (sessions || []).forEach(s => {
          h += '<tr><td style="padding:6px;font-family:monospace;">' + esc(s.device || '—') + '</td>'
            + '<td style="padding:6px;">' + (s.last_seen_at ? new Date(s.last_seen_at).toLocaleString() : '—') + '</td></tr>';
        });
        h += '</tbody></table></div></div>';
        detail.innerHTML = h;
      }catch(err){
        detail.innerHTML = '<p style="color:var(--danger);">' + esc(authErr(err.errorCode)) + '</p>';
      }
    });
  });
}
```

- [ ] **Step 2: Add the two confirm i18n keys** (all three dicts, same keys as Task 4 style):

en: `users_confirm_ban: 'Ban this account? All active sessions will be terminated.',` `users_confirm_unban: 'Unban this account?'`
fr: `users_confirm_ban: 'Bannir ce compte ? Toutes les sessions actives seront terminées.',` `users_confirm_unban: 'Débannir ce compte ?'`
ar: `users_confirm_ban: 'حظر هذا الحساب؟ سيتم إنهاء جميع الجلسات النشطة.',` `users_confirm_unban: 'إلغاء حظر هذا الحساب؟'`

- [ ] **Step 3: Remove now-dead local registry functions**

Delete (or leave inert, must not be referenced): `genAccessCode` (L3315–3325), `getRegistry` (L3283–3305), `saveRegistry` (L3306–3308), `regFind` (L3309–3314), `isApproved` (L3326–3329), and the `EMBEDDED_REGISTRY` constant + merge logic (L3282–3304). Verify no remaining references:

```powershell
node -e "const fs=require('fs');const s=fs.readFileSync('D:/v2.html','utf8');['getRegistry','saveRegistry','genAccessCode','regFind','isApproved','EMBEDDED_REGISTRY'].forEach(n=>{const c=(s.match(new RegExp(n,'g'))||[]).length;console.log(n,c);if(c>1)console.log('  STILL USED')});"
```

After removal, each of these may legitimately appear 0–1 times (definition site only → ideally 0). If any shows `>1`, a call site remains → find and fix it.

- [ ] **Step 4: Syntax-check** (repeat Task 1 check).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Rebuild admin Users panel against backend: accounts, ban, history, sessions"
```

---

### Task 6: Wire real config values + deploy

**Files:**
- Modify: `D:\v2.html` — `RD_CONFIG` block from Task 1; deploy copy `D:\Default Project\index.html`.

**Interfaces:**
- Consumes: deployed backend (backend plan Tasks 1–9).
- Produces: the live site talking to Supabase.

- [ ] **Step 1: Fill in real project values**

Replace the `<project-ref>` and `<anon-key>` placeholders in `RD_CONFIG` with the actual Supabase project URL and public anon key (from Project Settings → API). The anon key is public by design (it powers only RLS-denied access; all real auth is server-side). Keep `allowedOrigin` = the GitHub Pages origin.

- [ ] **Step 2: `node --check` final pass** (repeat Task 1 Step 2).

- [ ] **Step 3: Deploy to GitHub Pages** (existing flow)

```powershell
Copy-Item -LiteralPath "D:\v2.html" -Destination "D:\Default Project\index.html" -Force
$env:PATH += ";C:\Program Files\Git\cmd"
git add -A
git commit -m "Migrate frontend auth to Supabase backend"
git push origin main
```

Wait ~60s, then verify live at https://kossaitaguine331.github.io/repairdesk/.

- [ ] **Step 4: Live smoke test**

On the live site:
1. Log in `akuma/gouki` → admin nav appears; Akuma animation plays; Users panel lists accounts and shows login history for `akuma`.
2. Issue a code for a throwaway email; sign up in a **fresh/incognito browser** with that code → account created, shop starts empty.
3. Log out; log back in with the same credentials → token re-issued, shop data present (empty for the fresh account, full for any migrated legacy account).
4. Via the Users panel, ban that throwaway account → in the OTHER browser, attempt login → "This account has been banned" error shown server-side.

- [ ] **Step 5: First initialize the admin Users panel load with a local fallback refresh**

In `wireNav()` the `users` case (L1675) calls `renderUsersView(content)` synchronously. Keep it synchronous; `renderUsersView` now returns a Promise — the event handler may ignore the return value (`case 'users': renderUsersView(content); break;` needs no change; floating promise is acceptable). Verify the nav still switches and the panel fills in once the fetch resolves.

---

## Self-Review Notes

- **Spec coverage:** Section 4 (migration) → Task 3 `migrateShopDataForEmail`; Section 3 front-end consumable endpoints → Tasks 1–5; hardening #7 (ban instant-kill) is server-side (backend plan) and surfaced here via `auth_banned` on next action; i18n parity enforced in Task 4; `rd_sess` semantic change handled in Task 2.
- **Type consistency:** `RD.validateSession` returns `{valid, uid, name, role, banned}` and `beginSession` consumes `{uid,name,role,email,token}`; `authErr` maps every backend error string the spec can emit; `adminListAccounts` returns `{uid,email,name,approved,banned,created_at,last_login}` and the panel reads exactly those fields.
- **Placeholder scan:** `<project-ref>`/`<anon-key>` are fill-ins whose real values only exist after the user creates the project — replaced in Task 6 before any deploy.