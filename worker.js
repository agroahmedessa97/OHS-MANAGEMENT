// HSE multi-tenant API for Cloudflare Workers + D1.
const cors = (origin) => ({
  'Access-Control-Allow-Origin': origin || '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Vary': 'Origin'
});

const json = (data, status = 200, origin) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...cors(origin), 'Content-Type': 'application/json; charset=utf-8' }
  });

const enc = new TextEncoder();

async function hash(p, s) {
  const b = await crypto.subtle.importKey('raw', enc.encode(p), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(s), iterations: 180000, hash: 'SHA-256' },
    b,
    256
  );
  return [...new Uint8Array(bits)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function b64u(b) {
  return btoa(String.fromCharCode(...new Uint8Array(b)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function getSecret(env) {
  return env.JWT_SECRET || 'ohs-default-secret-key-change-in-production';
}

async function token(payload, secret) {
  const body = b64u(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = b64u(await crypto.subtle.sign('HMAC', key, enc.encode(body)));
  return body + '.' + sig;
}

async function verifyToken(t, secret) {
  try {
    const [body, sig] = t.split('.');
    if (!body || !sig) return null;
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    let s = sig.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const raw = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    if (!(await crypto.subtle.verify('HMAC', key, raw, enc.encode(body)))) return null;
    let b = body.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    return JSON.parse(atob(b));
  } catch {
    return null;
  }
}

const SYSTEM =
  'أنت مساعد متخصص في السلامة والصحة المهنية الصناعية. أجب بالعربية وبشكل عملي. عند تحليل الصور: (1) المشاهدات الظاهرة فقط (2) الأخطار المحتملة (3) تقييم أولي مع توضيح عدم اليقين (4) إجراء فوري (5) إجراءات تصحيحية ووقائية ومسؤول وموعد مقترح (6) مراجع مؤكدة فقط. لا تختلق نصوص قوانين أو أرقام NFPA، ولا تقدم اعتمادا قانونيا أو هندسيا نهائيا. عند خطر جسيم اقترح وقف النشاط وعزل الخطر وإبلاغ المختصين.';

async function auth(req, env) {
  const a = req.headers.get('Authorization') || '';
  const t = await verifyToken(a.replace(/^Bearer\s+/i, ''), getSecret(env));
  if (!t || t.exp < Date.now() / 1000 || !env.DB) return null;
  const m = await env.DB.prepare('SELECT role FROM memberships WHERE company_id=? AND user_id=?')
    .bind(t.companyId, t.userId)
    .first();
  return m ? { ...t, role: m.role } : null;
}

const code = () => 'HSE-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase();

export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin');
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors(origin) });
    const u = new URL(req.url);

    try {
      if (req.method === 'GET' && u.pathname === '/api/health') {
        return json({ ok: true, service: 'ohs-management', dbBound: Boolean(env.DB) }, 200, origin);
      }

      if (req.method === 'POST' && u.pathname === '/api/company/register') {
        if (!env.DB) return json({ error: 'قاعدة البيانات D1 غير مربوطة بالمشروع (DB).' }, 503, origin);
        const { company, name, email, username, password } = await req.json();
        if (!company || !name || !email || !username || !password || password.length < 10) {
          return json({ error: 'املأ الحقول كافة. يجب ألا تقل كلمة المرور عن 10 أحرف أو أرقام.' }, 400, origin);
        }
        const uid = crypto.randomUUID();
        const cid = crypto.randomUUID();
        const salt = crypto.randomUUID();
        const ph = await hash(password, salt);
        const cc = code();
        await env.DB.batch([
          env.DB.prepare('INSERT INTO companies(id,name,company_code) VALUES(?,?,?)').bind(cid, company, cc),
          env.DB.prepare('INSERT INTO users(id,email,username,name,password_hash) VALUES(?,?,?,?,?)')
            .bind(uid, email.trim().toLowerCase(), username.trim().toLowerCase(), name, salt + ':' + ph),
          env.DB.prepare("INSERT INTO memberships(id,company_id,user_id,role) VALUES(?,?,?,'owner')")
            .bind(crypto.randomUUID(), cid, uid)
        ]);
        return json({ ok: true, companyId: cid, companyCode: cc, message: 'تم إنشاء الشركة بنجاح.' }, 201, origin);
      }

      if (req.method === 'POST' && u.pathname === '/api/login') {
        if (!env.DB) return json({ error: 'قاعدة البيانات D1 غير مربوطة بالمشروع (DB).' }, 503, origin);
        const { companyCode, username, password } = await req.json();
        if (!companyCode || !username || !password) {
          return json({ error: 'أدخل كود الشركة واسم المستخدم وكلمة المرور.' }, 400, origin);
        }
        const normalizedCode = companyCode.trim().toUpperCase();
        const c = await env.DB.prepare('SELECT id,name FROM companies WHERE company_code=?').bind(normalizedCode).first();
        if (!c) return json({ error: 'كود الشركة غير صحيح.' }, 401, origin);
        const user = await env.DB.prepare('SELECT id,name,password_hash FROM users WHERE username=?')
          .bind(username.trim().toLowerCase())
          .first();
        if (!user) return json({ error: 'بيانات الدخول غير صحيحة.' }, 401, origin);
        const [salt, ph] = user.password_hash.split(':');
        if ((await hash(password, salt)) !== ph) return json({ error: 'بيانات الدخول غير صحيحة.' }, 401, origin);
        const m = await env.DB.prepare('SELECT company_id,role FROM memberships WHERE user_id=? AND company_id=?')
          .bind(user.id, c.id)
          .first();
        if (!m) return json({ error: 'الحساب غير تابع لهذه الشركة.' }, 403, origin);
        const tk = await token(
          { userId: user.id, companyId: c.id, role: m.role, exp: Math.floor(Date.now() / 1000) + 86400 },
          getSecret(env)
        );
        return json(
          {
            token: tk,
            user: {
              id: user.id,
              name: user.name,
              role: m.role,
              companyId: c.id,
              companyName: c.name,
              companyCode: normalizedCode
            }
          },
          200,
          origin
        );
      }

      const session = await auth(req, env);
      if (!session) return json({ error: 'غير مصرح بالدخول. يرجى تسجيل الدخول أولاً.' }, 401, origin);

      if (req.method === 'POST' && u.pathname === '/api/members') {
        if (!['owner', 'manager'].includes(session.role)) return json({ error: 'غير مسموح بهذا الإجراء.' }, 403, origin);
        const { name, username, email, password, role = 'member' } = await req.json();
        if (!name || !username || !email || !password || password.length < 10 || !['manager', 'member'].includes(role)) {
          return json({ error: 'بيانات العضو غير مكتملة أو كلمة المرور أقل من 10 أحرف.' }, 400, origin);
        }
        const emailN = email.trim().toLowerCase();
        const userN = username.trim().toLowerCase();
        const existingEmail = await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(emailN).first();
        if (existingEmail) return json({ error: 'البريد الإلكتروني مستخدم بالفعل.' }, 409, origin);
        const existingUsername = await env.DB.prepare('SELECT id FROM users WHERE username=?').bind(userN).first();
        if (existingUsername) return json({ error: 'اسم المستخدم مستخدم بالفعل.' }, 409, origin);
        const uid = crypto.randomUUID();
        const salt = crypto.randomUUID();
        await env.DB.batch([
          env.DB.prepare('INSERT INTO users(id,email,username,name,password_hash) VALUES(?,?,?,?,?)')
            .bind(uid, emailN, userN, name, salt + ':' + (await hash(password, salt))),
          env.DB.prepare('INSERT INTO memberships(id,company_id,user_id,role) VALUES(?,?,?,?)')
            .bind(crypto.randomUUID(), session.companyId, uid, role)
        ]);
        return json({ ok: true }, 201, origin);
      }

      if (req.method === 'GET' && u.pathname === '/api/members') {
        if (!['owner', 'manager'].includes(session.role)) return json({ error: 'غير مسموح بهذا الإجراء.' }, 403, origin);
        const rows = await env.DB.prepare(
          'SELECT u.name,u.username,u.email,m.role,m.created_at FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.company_id=?'
        )
          .bind(session.companyId)
          .all();
        return json(rows.results, 200, origin);
      }

      if (req.method === 'POST' && u.pathname === '/api/ai') {
        const body = await req.json();
        const q = body.question || '';
        if (!q && !body.images?.length) return json({ error: 'يرجى كتابة سؤال أو إرفاق صورة.' }, 400, origin);
        if (!env.OPENAI_API_KEY) return json({ error: 'لم يتم إعداد مفتاح OPENAI_API_KEY في الخادم.' }, 503, origin);
        const content = [{ type: 'text', text: q || 'حلل الصور المرفقة من منظور السلامة والصحة المهنية.' }];
        for (const img of (body.images || []).slice(0, 8)) {
          if (/^data:image\/(png|jpeg|webp);base64,/.test(img.data || '')) {
            content.push({ type: 'image_url', image_url: { url: img.data } });
          }
        }
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + env.OPENAI_API_KEY, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: env.AI_MODEL || 'gpt-4o-mini',
            messages: [
              { role: 'system', content: SYSTEM },
              { role: 'user', content }
            ],
            temperature: 0.2
          })
        });
        const data = await resp.json();
        if (!resp.ok) return json({ error: data.error?.message || 'تعذر إتمام التحليل من مزود الذكاء الاصطناعي.' }, 502, origin);
        const answer = data.choices?.[0]?.message?.content || '';
        await env.DB.prepare('INSERT INTO records(id,company_id,user_id,kind,payload) VALUES(?,?,?,?,?)')
          .bind(
            crypto.randomUUID(),
            session.companyId,
            session.userId,
            'ai_analysis',
            JSON.stringify({ question: q, answer, imageCount: body.images?.length || 0 })
          )
          .run();
        return json({ answer }, 200, origin);
      }

      if (req.method === 'POST' && u.pathname === '/api/records') {
        const body = await req.json();
        await env.DB.prepare('INSERT INTO records(id,company_id,user_id,kind,payload) VALUES(?,?,?,?,?)')
          .bind(
            crypto.randomUUID(),
            session.companyId,
            session.userId,
            String(body.kind || 'record'),
            JSON.stringify(body.payload || {})
          )
          .run();
        return json({ ok: true }, 201, origin);
      }

      if (req.method === 'GET' && u.pathname === '/api/records') {
        const rows = await env.DB.prepare(
          'SELECT id,kind,payload,created_at FROM records WHERE company_id=? ORDER BY created_at DESC LIMIT 200'
        )
          .bind(session.companyId)
          .all();
        return json(rows.results, 200, origin);
      }

      return json({ error: 'Not found' }, 404, origin);
    } catch (e) {
      if (String(e).includes('UNIQUE')) return json({ error: 'البريد الإلكتروني أو اسم المستخدم مستخدم بالفعل.' }, 409, origin);
      return json({ error: 'خطأ في الخادم', message: e.message }, 500, origin);
    }
  }
};
