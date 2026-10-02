import { compare } from 'bcryptjs';
const jsonHeaders = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'authorization, content-type, x-business-id',
    'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
};
function json(data, status = 200, extra = {}) {
    return new Response(JSON.stringify(data), { status, headers: { ...jsonHeaders, ...extra } });
}
function normalizePath(pathname) {
    if (pathname.length > 1 && pathname.endsWith('/'))
        pathname = pathname.slice(0, -1);
    return pathname.toLowerCase();
}
function normalizeBusinessType(raw) {
    const x = String(raw || 'general').toLowerCase().trim().replaceAll('-', '_');
    if (['pharmacy', 'pharmacy_business', 'medicine', 'medicine_business', 'medicine_shop', 'pharmacy_shop'].includes(x))
        return 'pharmacy';
    if (['family_finance', 'family', 'family_business', 'personal_finance', 'finance_family'].includes(x))
        return 'family_finance';
    if (['smart_tailor', 'tailor', 'tailor_business', 'tailoring', 'smarttailor'].includes(x))
        return 'smart_tailor';
    return 'general';
}
function normalizeBdPhone(v) {
    let s = String(v || '').replace(/[^0-9]/g, '');
    if (s.startsWith('00880'))
        s = s.slice(5);
    else if (s.startsWith('880'))
        s = s.slice(3);
    if (s.length === 10 && s.startsWith('1'))
        s = '0' + s;
    return /^01\d{9}$/.test(s) ? s : '';
}
function phoneCandidates(v) {
    const local = normalizeBdPhone(v);
    if (!local)
        return [v.trim()].filter(Boolean);
    return Array.from(new Set([local, '88' + local, '+88' + local, '880' + local.slice(1), '+880' + local.slice(1)]));
}
async function body(req) {
    const ct = req.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
        try {
            return (await req.json());
        }
        catch {
            return {};
        }
    }
    if (ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')) {
        const f = await req.formData();
        const out = {};
        for (const [k, v] of f.entries())
            out[k] = typeof v === 'string' ? v : v.name;
        return out;
    }
    try {
        return JSON.parse(await req.text());
    }
    catch {
        return {};
    }
}
function hex(bytes) { return [...bytes].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function sha256(v) { return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v)))); }
function randomToken(bytes = 32) { const a = new Uint8Array(bytes); crypto.getRandomValues(a); return hex(a); }
function sqlNow() { return new Date().toISOString().slice(0, 19).replace('T', ' '); }
function sqlFuture(seconds) { return new Date(Date.now() + seconds * 1000).toISOString().slice(0, 19).replace('T', ' '); }
async function verifyLegacyPassword(password, hash) {
    if (!hash)
        return false;
    try {
        const normalized = hash.startsWith('$2y$') ? '$2b$' + hash.slice(4) : hash;
        return await compare(password, normalized);
    }
    catch {
        return false;
    }
}
function cookieMap(req) {
    const out = {};
    for (const part of (req.headers.get('cookie') || '').split(';')) {
        const i = part.indexOf('=');
        if (i < 0)
            continue;
        out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    }
    return out;
}
function bearer(req) {
    const h = req.headers.get('authorization') || '';
    return h.toLowerCase().startsWith('bearer ') ? h.slice(7).trim() : '';
}
async function resolveAuth(req, env) {
    const token = bearer(req);
    if (token) {
        const hash = await sha256(token);
        const row = await env.DB.prepare(`
      SELECT t.id AS token_id,t.user_id,t.business_id,t.expires_at,
             u.name,u.email,u.phone,u.role,u.permissions,u.avatar,u.is_active,
             b.name AS business_name,b.currency_symbol,b.subscription_status,b.business_type
      FROM mobile_api_tokens t
      JOIN users u ON u.id=t.user_id
      LEFT JOIN businesses b ON b.id=t.business_id
      WHERE t.token_hash=? AND u.is_active=1 AND (t.expires_at IS NULL OR t.expires_at>CURRENT_TIMESTAMP)
      LIMIT 1`).bind(hash).first();
        if (row) {
            await env.DB.prepare('UPDATE mobile_api_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE id=?').bind(row.token_id).run();
            return row;
        }
    }
    const sid = cookieMap(req)['hisabi_session'];
    if (!sid)
        return null;
    const hash = await sha256(sid);
    const row = await env.DB.prepare(`
    SELECT s.user_id,s.business_id,s.role,s.business_type,s.expires_at,
           u.name,u.email,u.phone,u.permissions,u.avatar,u.is_active,
           b.name AS business_name,b.currency_symbol,b.subscription_status
    FROM cf_web_sessions s
    JOIN users u ON u.id=s.user_id
    LEFT JOIN businesses b ON b.id=s.business_id
    WHERE s.token_hash=? AND s.expires_at>CURRENT_TIMESTAMP AND u.is_active=1 LIMIT 1`).bind(hash).first();
    if (!row)
        return null;
    await env.DB.prepare('UPDATE cf_web_sessions SET last_used_at=CURRENT_TIMESTAMP WHERE token_hash=?').bind(hash).run();
    return row;
}
async function selectLoginUser(env, identity, password, requestedType, mobileAuto) {
    const candidates = phoneCandidates(identity);
    const email = identity.includes('@');
    let q = `SELECT u.*, b.name AS business_name,b.currency_symbol,b.subscription_status,b.business_type
           FROM users u LEFT JOIN businesses b ON b.id=u.business_id WHERE u.is_active=1 AND `;
    let args = [];
    if (email) {
        q += 'LOWER(u.email)=LOWER(?)';
        args = [identity];
    }
    else {
        const ps = candidates.map(() => '?').join(',');
        q += `(u.email=? OR u.phone IN (${ps}))`;
        args = [identity, ...candidates];
    }
    q += ' ORDER BY u.id DESC LIMIT 50';
    const rows = (await env.DB.prepare(q).bind(...args).all()).results || [];
    for (const u of rows) {
        if (String(u.role || '') === 'super_admin')
            continue;
        const bt = normalizeBusinessType(u.business_type);
        if (!mobileAuto && requestedType && requestedType !== 'auto' && bt !== requestedType)
            continue;
        if (await verifyLegacyPassword(password, String(u.password || ''))) {
            u.business_type = bt;
            return u;
        }
    }
    return null;
}
async function loginHandler(req, env) {
    if (req.method !== 'POST')
        return json({ success: false, error: 'POST required' }, 405);
    const d = await body(req);
    const identity = String(d.identity ?? d.email ?? d.phone ?? '').trim();
    const password = String(d.password ?? '');
    const rawType = String(d.business_type ?? d.type ?? d.module ?? 'auto');
    if (!identity || !password)
        return json({ success: false, error: 'Email/phone and password required' }, 422);
    const normalizedRaw = rawType.toLowerCase().trim();
    const mobileAuto = ['', 'auto', 'detect', 'business', 'app'].includes(normalizedRaw);
    const requestedType = mobileAuto ? 'auto' : normalizeBusinessType(rawType);
    const user = await selectLoginUser(env, identity, password, requestedType, mobileAuto);
    if (!user)
        return json({ success: false, error: 'Incorrect email, phone or password' }, 401);
    const token = randomToken(32);
    const hash = await sha256(token);
    const expires = sqlFuture(90 * 24 * 3600);
    await env.DB.prepare(`INSERT INTO mobile_api_tokens(user_id,business_id,token_hash,device_name,expires_at,last_used_at,created_at)
                        VALUES(?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`)
        .bind(Number(user.id), Number(user.business_id || 0), hash, String(d.device_name || 'Cloudflare Client'), expires).run();
    await env.DB.prepare('UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?').bind(Number(user.id)).run();
    return json({ success: true, token, expires_at: expires, requires_business_setup: Number(user.business_id || 0) <= 0, business_type: user.business_type, user: {
            id: Number(user.id), name: user.name || '', email: user.email || '', phone: user.phone || '', avatar: user.avatar || '', role: user.role || '',
            business_id: Number(user.business_id || 0), business_name: user.business_name || '', currency_symbol: user.currency_symbol || '৳', business_type: user.business_type
        } });
}
async function webLoginHandler(req, env, portal) {
    const d = await body(req);
    const identity = String(d.email ?? d.identity ?? d.phone ?? '').trim();
    const password = String(d.password ?? '');
    const user = await selectLoginUser(env, identity, password, portal, false);
    if (!user)
        return json({ success: false, error: 'Incorrect email, phone or password' }, 401);
    const token = randomToken(32);
    const hash = await sha256(token);
    const expires = sqlFuture(2 * 3600);
    await env.DB.prepare('INSERT INTO cf_web_sessions(token_hash,user_id,business_id,role,business_type,expires_at) VALUES(?,?,?,?,?,?)')
        .bind(hash, Number(user.id), Number(user.business_id || 0), String(user.role || 'staff'), String(user.business_type || 'general'), expires).run();
    const target = user.business_type === 'pharmacy' ? '/pharmacy/pharmacy_dashboard.php' : user.business_type === 'smart_tailor' ? '/tailor/tailor_dashboard.php' : user.business_type === 'family_finance' ? '/family/index.php' : '/business/dashboard.php';
    return json({ success: true, redirect: target, user: { id: Number(user.id), name: user.name, business_id: Number(user.business_id || 0), role: user.role, business_type: user.business_type } }, 200, {
        'set-cookie': `hisabi_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=7200`
    });
}
async function meHandler(req, env) {
    const u = await resolveAuth(req, env);
    if (!u)
        return json({ success: false, error: 'Invalid or expired API token' }, 401);
    return json({ success: true, user: { id: Number(u.user_id || u.id || 0), name: u.name || '', email: u.email || '', phone: u.phone || '', role: u.role || '', permissions: u.permissions || null, avatar: u.avatar || '', business_id: Number(u.business_id || 0), business_name: u.business_name || '', currency_symbol: u.currency_symbol || '৳', subscription_status: u.subscription_status || '', business_type: normalizeBusinessType(u.business_type) } });
}
async function logoutHandler(req, env) {
    const b = bearer(req);
    if (b)
        await env.DB.prepare('DELETE FROM mobile_api_tokens WHERE token_hash=?').bind(await sha256(b)).run();
    const sid = cookieMap(req)['hisabi_session'];
    if (sid)
        await env.DB.prepare('DELETE FROM cf_web_sessions WHERE token_hash=?').bind(await sha256(sid)).run();
    return json({ success: true }, 200, { 'set-cookie': 'hisabi_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' });
}
const listRouteTable = {
    '/api/v1/branches/list.php': 'branches', '/api/v1/branches/list': 'branches',
    '/api/v1/products/list.php': 'products', '/api/v1/products/list': 'products',
    '/api/v1/customers/list.php': 'customers', '/api/v1/customers/list': 'customers',
    '/api/v1/suppliers/list.php': 'suppliers', '/api/v1/suppliers/list': 'suppliers',
    '/api/v1/sales/list.php': 'sales', '/api/v1/sales/list': 'sales',
    '/api/v1/expenses/list.php': 'expenses', '/api/v1/expenses/list': 'expenses',
    '/api/v1/invoices/list.php': 'sales', '/api/v1/invoices/list': 'sales',
    '/api/v1/purchases/list.php': 'purchases', '/api/v1/purchases/list': 'purchases'
};
async function listHandler(req, env, table) {
    const u = await resolveAuth(req, env);
    if (!u)
        return json({ success: false, error: 'Unauthorized' }, 401);
    const url = new URL(req.url);
    const requested = Number(req.headers.get('x-business-id') || url.searchParams.get('selected_business_id') || 0);
    const businessId = requested > 0 ? requested : Number(u.business_id || 0);
    if (requested > 0 && requested !== Number(u.business_id || 0)) {
        const allowed = await env.DB.prepare('SELECT 1 FROM user_business_access WHERE user_id=? AND business_id=? LIMIT 1').bind(Number(u.user_id || 0), requested).first();
        if (!allowed)
            return json({ success: false, error: 'Business access denied' }, 403);
    }
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') || 50)));
    const offset = Math.max(0, Number(url.searchParams.get('offset') || 0));
    let q = `SELECT * FROM \`${table}\` WHERE business_id=?`;
    const args = [businessId];
    if (url.searchParams.get('q') && ['products', 'customers', 'suppliers'].includes(table)) {
        q += ' AND (name LIKE ? OR phone LIKE ? OR email LIKE ?)';
        const s = '%' + url.searchParams.get('q') + '%';
        args.push(s, s, s);
    }
    if (table === 'branches')
        q += ' AND (deleted_at IS NULL)';
    if (table === 'products')
        q += ' AND (deleted_at IS NULL)';
    q += ' ORDER BY id DESC LIMIT ? OFFSET ?';
    args.push(limit, offset);
    const rows = (await env.DB.prepare(q).bind(...args).all()).results || [];
    return json({ success: true, data: rows, items: rows, count: rows.length, business_id: businessId });
}
async function dashboardSummary(req, env) {
    const u = await resolveAuth(req, env);
    if (!u)
        return json({ success: false, error: 'Unauthorized' }, 401);
    const b = Number(u.business_id || 0);
    const [sales, expenses, customers, products, due] = await env.DB.batch([
        env.DB.prepare("SELECT COALESCE(SUM(grand_total),0) v, COUNT(*) c FROM sales WHERE business_id=? AND date(sale_date)=date('now','localtime')").bind(b),
        env.DB.prepare("SELECT COALESCE(SUM(amount),0) v, COUNT(*) c FROM expenses WHERE business_id=? AND date(expense_date)=date('now','localtime')").bind(b),
        env.DB.prepare('SELECT COUNT(*) c FROM customers WHERE business_id=?').bind(b),
        env.DB.prepare('SELECT COUNT(*) c FROM products WHERE business_id=? AND is_active=1 AND deleted_at IS NULL').bind(b),
        env.DB.prepare("SELECT COALESCE(SUM(due_amount),0) v FROM sales WHERE business_id=? AND due_amount>0 AND status!='cancelled'").bind(b)
    ]);
    const one = (r) => r.results?.[0] || {};
    return json({ success: true, summary: { today_sales: Number(one(sales).v || 0), today_sales_count: Number(one(sales).c || 0), today_expense: Number(one(expenses).v || 0), today_expense_count: Number(one(expenses).c || 0), customers: Number(one(customers).c || 0), products: Number(one(products).c || 0), total_due: Number(one(due).v || 0) } });
}
async function uploadHandler(req, env) {
    const u = await resolveAuth(req, env);
    if (!u)
        return json({ success: false, error: 'Unauthorized' }, 401);
    if (req.method !== 'POST')
        return json({ success: false, error: 'POST required' }, 405);
    const form = await req.formData();
    const file = form.get('file');
    if (!(file instanceof File))
        return json({ success: false, error: 'file required' }, 422);
    if (file.size > 10 * 1024 * 1024)
        return json({ success: false, error: 'File too large' }, 413);
    const safe = file.name.replace(/[^A-Za-z0-9._-]+/g, '_');
    const key = `business/${Number(u.business_id || 0)}/${Date.now()}_${crypto.randomUUID()}_${safe}`;
    await env.UPLOADS.put(key, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
    return json({ success: true, key, url: `/uploads/${key}` });
}
async function uploadGet(req, env, path) {
    const key = decodeURIComponent(path.replace(/^\/uploads\//, ''));
    const obj = await env.UPLOADS.get(key);
    if (!obj)
        return new Response('Not found', { status: 404 });
    const h = new Headers();
    obj.writeHttpMetadata(h);
    h.set('etag', obj.httpEtag);
    h.set('cache-control', 'public, max-age=86400');
    return new Response(obj.body, { headers: h });
}
async function route(req, env) {
    if (req.method === 'OPTIONS')
        return new Response(null, { status: 204, headers: jsonHeaders });
    const url = new URL(req.url);
    const p = normalizePath(url.pathname);
    if (p === '/health' || p === '/api/health') {
        try {
            const row = await env.DB.prepare('SELECT COUNT(*) tables FROM sqlite_master WHERE type=\'table\'').first();
            return json({ ok: true, service: 'Hisabi Bondhu Cloudflare', d1: true, tables: Number(row?.tables || 0), time: new Date().toISOString() });
        }
        catch (e) {
            return json({ ok: false, error: String(e) }, 500);
        }
    }
    if ((p === '/api/v1/auth/login.php' || p === '/api/v1/auth/login') && req.method === 'POST')
        return loginHandler(req, env);
    if ((p === '/api/v1/auth/me.php' || p === '/api/v1/auth/me') && req.method === 'GET')
        return meHandler(req, env);
    if ((p === '/api/v1/auth/logout.php' || p === '/api/v1/auth/logout') && req.method === 'POST')
        return logoutHandler(req, env);
    if (p === '/api/v1/dashboard/summary.php' || p === '/api/v1/dashboard/summary')
        return dashboardSummary(req, env);
    if (listRouteTable[p])
        return listHandler(req, env, listRouteTable[p]);
    if (p === '/api/v1/files/upload' || p === '/api/v1/files/upload.php')
        return uploadHandler(req, env);
    if (p.startsWith('/uploads/'))
        return uploadGet(req, env, url.pathname);
    if (p === '/login.php' && req.method === 'POST')
        return webLoginHandler(req, env, 'general');
    if (p === '/pharmacy/login.php' && req.method === 'POST')
        return webLoginHandler(req, env, 'pharmacy');
    if (p === '/tailor/login.php' && req.method === 'POST')
        return webLoginHandler(req, env, 'smart_tailor');
    if (p === '/family/login.php' && req.method === 'POST')
        return webLoginHandler(req, env, 'family_finance');
    return env.ASSETS.fetch(req);
}
export default { fetch: route };
