// HSE Multi-Tenant SaaS API & High-Precision OHS AI Engine (Cloudflare Workers + D1 + Static Assets)
const cors = (origin) => ({
  'Access-Control-Allow-Origin': origin || '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  'Vary': 'Origin'
});

const json = (data, status = 200, origin) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...cors(origin), 'Content-Type': 'application/json; charset=utf-8' }
  });

const enc = new TextEncoder();

const DEFAULT_PERMISSIONS = {
  ai: true,
  records: true,
  documents: true,
  members: false,
  delete_records: false
};

const FULL_PERMISSIONS = {
  ai: true,
  records: true,
  documents: true,
  members: true,
  delete_records: true
};

function normalizePermissions(raw, role = 'member') {
  const base = role === 'owner' ? { ...FULL_PERMISSIONS } : { ...DEFAULT_PERMISSIONS };
  let parsed = raw;
  if (typeof raw === 'string') {
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = {};
    }
  }
  if (!parsed || typeof parsed !== 'object') return base;
  return {
    ai: parsed.ai !== undefined ? Boolean(parsed.ai) : base.ai,
    records: parsed.records !== undefined ? Boolean(parsed.records) : base.records,
    documents: parsed.documents !== undefined ? Boolean(parsed.documents) : base.documents,
    members: role === 'owner' ? true : Boolean(parsed.members),
    delete_records: role === 'owner' ? true : Boolean(parsed.delete_records)
  };
}

async function hash(p, s) {
  const b = await crypto.subtle.importKey('raw', enc.encode(p), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(s), iterations: 100000, hash: 'SHA-256' },
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

const EXPERT_SYSTEM_PROMPT = `أنت كبير مستشاري السلامة والصحة المهنية (HSE Lead Consultant) وخبير نظم الإدارة الصناعية (ISO 45001, ISO 14001, ISO 9001, FSSC 22000, HACCP, NFPA, الكود المصري للدفاع المدني، وقانون العمل المصري رقم 14 لسنة 2025 والقرارات الوزارية 248 و249 و250 لسنة 2026).

منهجية التفكير والاحترافية القصوى:
1. التحليل العميق والمنظم: فكّك المشكلة من الجذور (هندسية، تشغيلية، سلوكية، وتنظيمية) وقدّم حلولاً قابلة للتنفيذ الفوري في المصانع وخطوط الإنتاج والمخازن والمرافق.
2. التدرج في الضوابط (Hierarchy of Controls): رتّب توصياتك دائماً وفق التسلسل القياسي: الإزالة (Elimination) -> الاستبدال (Substitution) -> الضوابط الهندسية (Engineering Controls) -> الضوابط الإدارية والتدريب (Administrative Controls) -> مهمات الوقاية الشخصية (PPE).
3. تحليل الصور والمخططات بدقة عالية:
   - ابدأ بقائمة (المشاهدات البصرية المؤكدة في الصورة فقط) دون تخمين غير مرئي.
   - حدّد (المخاطر المحتملة وتصنيف شدتها).
   - قدّم (إجراءات الاحتواء الفورية خلال 24 ساعة) ثم (الإجراءات التصحيحية والوقائية CAPA) مع تحديد المسؤول ومؤشر التحقق من الإغلاق.
   - نبّه بوضوح أن الفحص البصري للصورة استرشادي ولا يغني عن المعاينة الميدانية والقياسات الهندسية المعتمدة.
4. تحليل الحوادث والأسباب الجذرية (RCA): افصل بين الوقائع المؤكدة والافتراضات، واستخدم منهجية (5 Whys) و(Fishbone) دون إلقاء اللوم الشخصي، ثم ضع مصفوفة CAPA واضحة (الإجراء، المسؤول، الموعد، دليل الإغلاق).
5. تقييم المخاطر (5×5): احسب الشدة × الاحتمالية قبل التحكم وبعد التحكم بوضوح، ولا تختلق أرقاماً غير معطاة؛ وإذا نقصت معطيات مهمة اذكر الافتراضات بوضوح واقترح أسئلة متابعة ذكية.
6. الدقة التشريعية: عند الإشارة لقانون العمل المصري أو القرارات الوزارية أو أكواد NFPA والكود المصري، التزم بالدقة ولا تنسب أرقام مواد أو حسابات تصميمية نهائية دون مصدر موثوق في السياق، وأشر إلى ضرورة الاعتماد الهندسي الرسمي عند اللزوم.
7. الخطر الجسيم والوشيك: إذا تضمنت الحالة أو الصورة خطراً جسيماً وشيكاً (كهرباء مكشوفة عالية الجهد، عمل على ارتفاع بدون حزام أمان، تسرب غاز/مواد خطرة، حريق أو انهيار)، ابدأ فوراً بتحذير عاجل لإيقاف النشاط بأمان وعزل المنطقة وتفعيل خطة الطوارئ.
8. الأسلوب: لغة عربية مهنية واضحة ومنسقة في نقاط وعناوين عملية مباشرة بدون حشو أو مقدمات إنشائية.`;

let dbInitialized = false;

async function ensureDatabaseReady(env) {
  if (!env.DB || dbInitialized) return;
  const defaultJson = JSON.stringify(DEFAULT_PERMISSIONS);
  await env.DB.batch([
    env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS companies(id TEXT PRIMARY KEY, name TEXT NOT NULL, company_code TEXT NOT NULL UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP)'
    ),
    env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, username TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)'
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS memberships(id TEXT PRIMARY KEY, company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL CHECK(role IN ('owner','manager','member')), permissions_json TEXT NOT NULL DEFAULT '${defaultJson}', created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(company_id,user_id))`
    ),
    env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES users(id), kind TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)'
    ),
    env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY, company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL, object_key TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)'
    ),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_members_company ON memberships(company_id)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_records_company ON records(company_id)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_records_kind ON records(company_id, kind)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_docs_company ON documents(company_id)')
  ]);
  try {
    const sql = `ALTER TABLE memberships ADD COLUMN permissions_json TEXT NOT NULL DEFAULT '${defaultJson}'`;
    await env.DB.prepare(sql).run();
  } catch {}
  dbInitialized = true;
}

async function auth(req, env) {
  const a = req.headers.get('Authorization') || '';
  const t = await verifyToken(a.replace(/^Bearer\s+/i, ''), getSecret(env));
  if (!t || t.exp < Date.now() / 1000 || !env.DB) return null;
  await ensureDatabaseReady(env);
  const m = await env.DB.prepare(
    'SELECT role, permissions_json FROM memberships WHERE company_id=? AND user_id=?'
  )
    .bind(t.companyId, t.userId)
    .first();
  if (!m) return null;
  const permissions = normalizePermissions(m.permissions_json, m.role);
  return { ...t, role: m.role, permissions };
}

const code = () => 'HSE-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase();

async function parseJsonBody(req) {
  try {
    return await req.json();
  } catch {
    return null;
  }
}

async function callGeminiProvider(env, promptText, validImgs, temperature) {
  const rawKey = String(env.GEMINI_API_KEY || '').trim();
  if (!rawKey) throw new Error('NO_AI_KEY');

  const modelsToTry = [
    env.GEMINI_MODEL || 'gemini-2.5-flash',
    'gemini-2.5-pro',
    'gemini-2.0-flash'
  ];
  const uniqueModels = Array.from(new Set(modelsToTry.filter(Boolean)));
  let lastErr = null;

  for (const model of uniqueModels) {
    try {
      const parts = [{ text: promptText }];
      for (const img of validImgs) {
        parts.push({ inlineData: { mimeType: img.mimeType, data: img.base64 } });
      }
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(rawKey)}`;
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: EXPERT_SYSTEM_PROMPT }] },
          contents: [{ role: 'user', parts }],
          generationConfig: {
            temperature,
            maxOutputTokens: 4096
          }
        })
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        const apiMsg = data.error?.message || `Gemini HTTP ${resp.status}`;
        lastErr = new Error(`${model}: ${apiMsg}`);
        continue;
      }
      const candParts = data.candidates?.[0]?.content?.parts || [];
      const text = candParts.map((p) => p.text || '').join('\n').trim();
      if (text) return { answer: text, modelUsed: model };
      lastErr = new Error(`${model}: رد فارغ من النموذج`);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error('تعذر إتمام التحليل من Gemini.');
}

async function callOpenAiProvider(env, promptText, validImgs, temperature) {
  const modelsToTry = [
    env.AI_MODEL || 'gpt-4o',
    'gpt-4o-mini'
  ];
  const uniqueModels = Array.from(new Set(modelsToTry));
  let lastErr = null;

  for (const model of uniqueModels) {
    try {
      const content = [{ type: 'text', text: promptText }];
      for (const img of validImgs) {
        content.push({ type: 'image_url', image_url: { url: img.dataUrl, detail: 'high' } });
      }
      const resp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + env.OPENAI_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: EXPERT_SYSTEM_PROMPT },
            { role: 'user', content }
          ],
          temperature,
          max_tokens: 4096
        })
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        lastErr = new Error(data.error?.message || `OpenAI HTTP ${resp.status}`);
        continue;
      }
      const text = (data.choices?.[0]?.message?.content || '').trim();
      if (text) return { answer: text, modelUsed: model };
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error('تعذر إتمام التحليل من OpenAI.');
}

async function runHighPrecisionAI(env, promptText, images = [], mode = 'flexible') {
  const validImgs = (images || [])
    .slice(0, 8)
    .map((img) => {
      const m = /^data:(image\/(?:png|jpeg|jpg|webp|gif));base64,(.+)$/i.exec(img?.data || '');
      return m ? { mimeType: m[1].toLowerCase(), base64: m[2], dataUrl: img.data } : null;
    })
    .filter(Boolean);

  const temperature = mode === 'deep_analysis' ? 0.25 : mode === 'quick_action' ? 0.3 : 0.35;

  const hasGemini = Boolean(env.GEMINI_API_KEY);
  const hasOpenAI = Boolean(env.OPENAI_API_KEY);

  if (!hasGemini && !hasOpenAI) {
    throw new Error('NO_AI_KEY');
  }

  // Automatic failover between Gemini and OpenAI for maximum reliability and accuracy
  if (hasGemini && hasOpenAI) {
    try {
      return await callGeminiProvider(env, promptText, validImgs, temperature);
    } catch {
      return await callOpenAiProvider(env, promptText, validImgs, temperature);
    }
  }

  if (hasGemini) {
    return await callGeminiProvider(env, promptText, validImgs, temperature);
  }

  return await callOpenAiProvider(env, promptText, validImgs, temperature);
}

export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin');
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors(origin) });
    const u = new URL(req.url);

    try {
      if (req.method === 'GET' && u.pathname === '/api/health') {
        let tablesReady = false;
        if (env.DB) {
          try {
            await ensureDatabaseReady(env);
            tablesReady = true;
          } catch {
            tablesReady = false;
          }
        }
        return json(
          {
            ok: true,
            service: 'ohs-management',
            dbBound: Boolean(env.DB),
            tablesReady,
            aiConfigured: Boolean(env.GEMINI_API_KEY || env.OPENAI_API_KEY),
            aiProviders: {
              gemini: Boolean(env.GEMINI_API_KEY),
              openai: Boolean(env.OPENAI_API_KEY)
            },
            assetsBound: Boolean(env.ASSETS)
          },
          200,
          origin
        );
      }

      if (req.method === 'POST' && u.pathname === '/api/company/register') {
        if (!env.DB) return json({ error: 'قاعدة البيانات D1 غير مربوطة بالمشروع (DB).' }, 503, origin);
        await ensureDatabaseReady(env);
        const body = await parseJsonBody(req);
        if (!body) return json({ error: 'صيغة البيانات المرسلة غير صالحة.' }, 400, origin);

        const { company, name, email, username, password } = body;
        if (!company || !name || !email || !username || !password || String(password).length < 3) {
          return json({ error: 'املأ الحقول كافة. يجب ألا تقل كلمة المرور عن 3 أحرف أو أرقام.' }, 400, origin);
        }

        const emailN = String(email).trim().toLowerCase();
        const userN = String(username).trim().toLowerCase();

        const existingEmail = await env.DB.prepare('SELECT id FROM users WHERE LOWER(TRIM(email))=?').bind(emailN).first();
        if (existingEmail) {
          return json({ error: 'هذا البريد الإلكتروني مسجّل بالفعل. استخدم بريداً آخر أو سجّل الدخول.' }, 409, origin);
        }

        const existingUser = await env.DB.prepare('SELECT id FROM users WHERE username=?').bind(userN).first();
        if (existingUser) {
          return json({ error: 'اسم المستخدم هذا محجوز بالفعل. اختر اسم مستخدم آخر.' }, 409, origin);
        }

        const uid = crypto.randomUUID();
        const cid = crypto.randomUUID();
        const salt = crypto.randomUUID();
        const ph = await hash(String(password), salt);
        const cc = code();

        await env.DB.batch([
          env.DB.prepare('INSERT INTO companies(id,name,company_code) VALUES(?,?,?)')
            .bind(cid, String(company).trim(), cc),
          env.DB.prepare('INSERT INTO users(id,email,username,name,password_hash) VALUES(?,?,?,?,?)')
            .bind(uid, emailN, userN, String(name).trim(), salt + ':' + ph),
          env.DB.prepare(
            "INSERT INTO memberships(id,company_id,user_id,role,permissions_json) VALUES(?,?,?,'owner',?)"
          ).bind(crypto.randomUUID(), cid, uid, JSON.stringify(FULL_PERMISSIONS))
        ]);

        return json({ ok: true, companyId: cid, companyCode: cc, message: 'تم إنشاء الشركة بنجاح.' }, 201, origin);
      }


      if (req.method === 'POST' && u.pathname === '/api/auth/forgot-password') {
        if (!env.DB) return json({ error: 'قاعدة البيانات D1 غير مربوطة بالمشروع (DB).' }, 503, origin);
        await ensureDatabaseReady(env);
        const body = await parseJsonBody(req);
        if (!body) return json({ error: 'صيغة البيانات المرسلة غير صالحة.' }, 400, origin);

        const emailN = String(body.email || '').trim().toLowerCase();
        if (!emailN || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailN)) {
          return json({ error: 'أدخل بريداً إلكترونياً صحيحاً ومسجلاً في النظام.' }, 400, origin);
        }

        const existing = await env.DB.prepare('SELECT id, name, email FROM users WHERE LOWER(TRIM(email))=?')
          .bind(emailN)
          .first();
        if (!existing) {
          return json({ error: 'هذا البريد الإلكتروني غير مسجّل في النظام.' }, 404, origin);
        }

        const otpCode = String(Math.floor(100000 + Math.random() * 900000));
        const expiresAt = Date.now() + 15 * 60 * 1000;
        const otpPayload = JSON.stringify({
          userId: existing.id,
          email: existing.email,
          otp: otpCode,
          expiresAt
        });

        if (env.OTP_KV && typeof env.OTP_KV.put === 'function') {
          await env.OTP_KV.put('pwd_reset:' + emailN, otpPayload, { expirationTtl: 900 });
        }

        let deliveredViaEmail = false;
        const resendKey = String(env.RESEND_API_KEY || '').trim();
        const fromEmail = String(env.FROM_EMAIL || 'onboarding@resend.dev').trim();
        if (resendKey) {
          try {
            const mailRes = await fetch('https://api.resend.com/emails', {
              method: 'POST',
              headers: {
                'Authorization': 'Bearer ' + resendKey,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                from: fromEmail,
                to: [existing.email],
                subject: 'رمز استعادة كلمة المرور — منصة السلامة والصحة المهنية (HSE)',
                html: `<div dir="rtl" style="font-family:Cairo,Arial,sans-serif;line-height:1.7;">
                  <h2>استعادة كلمة المرور</h2>
                  <p>مرحباً ${existing.name || ''}،</p>
                  <p>رمز التحقق الخاص باستعادة كلمة المرور هو: <strong style="font-size:20px;letter-spacing:3px;">${otpCode}</strong></p>
                  <p>صلاحية الرمز 15 دقيقة.</p>
                </div>`
              })
            });
            deliveredViaEmail = mailRes.ok;
          } catch {
            deliveredViaEmail = false;
          }
        }

        return json({
          ok: true,
          email: existing.email,
          deliveredViaEmail,
          expiresInMinutes: 15,
          ...(deliveredViaEmail ? {} : { debugOtp: otpCode })
        }, 200, origin);
      }

      if (req.method === 'POST' && u.pathname === '/api/auth/reset-password') {
        if (!env.DB) return json({ error: 'قاعدة البيانات D1 غير مربوطة بالمشروع (DB).' }, 503, origin);
        await ensureDatabaseReady(env);
        const body = await parseJsonBody(req);
        if (!body) return json({ error: 'صيغة البيانات المرسلة غير صالحة.' }, 400, origin);

        const emailN = String(body.email || '').trim().toLowerCase();
        const otpInput = String(body.otp || '').trim();
        const newPassword = String(body.newPassword || '');

        if (!emailN || !otpInput || newPassword.length < 3) {
          return json({ error: 'أدخل البريد الإلكتروني ورمز التحقق وكلمة المرور الجديدة (3 أحرف أو أرقام على الأقل).' }, 400, origin);
        }

        let storedRecord = null;
        if (env.OTP_KV && typeof env.OTP_KV.get === 'function') {
          const rawKv = await env.OTP_KV.get('pwd_reset:' + emailN);
          if (rawKv) {
            try { storedRecord = JSON.parse(rawKv); } catch { storedRecord = null; }
          }
        }

        if (!storedRecord || String(storedRecord.otp) !== otpInput || Number(storedRecord.expiresAt || 0) < Date.now()) {
          return json({ error: 'رمز التحقق غير صحيح أو منتهي الصلاحية.' }, 400, origin);
        }

        const userRow = await env.DB.prepare('SELECT id FROM users WHERE LOWER(TRIM(email))=?')
          .bind(emailN)
          .first();
        if (!userRow) {
          return json({ error: 'الحساب المرتبط بهذا البريد غير موجود.' }, 404, origin);
        }

        const newSalt = crypto.randomUUID();
        const newHash = await hash(newPassword, newSalt);
        await env.DB.prepare('UPDATE users SET password_hash=? WHERE id=?')
          .bind(newSalt + ':' + newHash, userRow.id)
          .run();

        if (env.OTP_KV && typeof env.OTP_KV.delete === 'function') {
          await env.OTP_KV.delete('pwd_reset:' + emailN);
        }

        return json({ ok: true, message: 'تم تحديث كلمة المرور بنجاح. يمكنك الآن تسجيل الدخول بكلمة المرور الجديدة.' }, 200, origin);
      }

      if (req.method === 'POST' && u.pathname === '/api/login') {
        if (!env.DB) return json({ error: 'قاعدة البيانات D1 غير مربوطة بالمشروع (DB).' }, 503, origin);
        await ensureDatabaseReady(env);
        const body = await parseJsonBody(req);
        if (!body) return json({ error: 'صيغة البيانات المرسلة غير صالحة.' }, 400, origin);

        const { companyCode, username, password } = body;
        if (!companyCode || !username || !password) {
          return json({ error: 'أدخل كود الشركة واسم المستخدم وكلمة المرور.' }, 400, origin);
        }
        const normalizedCode = String(companyCode).trim().toUpperCase();
        const c = await env.DB.prepare('SELECT id,name FROM companies WHERE company_code=?').bind(normalizedCode).first();
        if (!c) return json({ error: 'كود الشركة غير صحيح.' }, 401, origin);
        const user = await env.DB.prepare('SELECT id,name,password_hash FROM users WHERE username=?')
          .bind(String(username).trim().toLowerCase())
          .first();
        if (!user) return json({ error: 'بيانات الدخول غير صحيحة.' }, 401, origin);
        const [salt, ph] = user.password_hash.split(':');
        if ((await hash(String(password), salt)) !== ph) return json({ error: 'بيانات الدخول غير صحيحة.' }, 401, origin);
        const m = await env.DB.prepare(
          'SELECT company_id,role,permissions_json FROM memberships WHERE user_id=? AND company_id=?'
        )
          .bind(user.id, c.id)
          .first();
        if (!m) return json({ error: 'الحساب غير تابع لهذه الشركة.' }, 403, origin);
        const permissions = normalizePermissions(m.permissions_json, m.role);
        const exp = Math.floor(Date.now() / 1000) + 86400;
        const tk = await token(
          { userId: user.id, companyId: c.id, role: m.role, exp },
          getSecret(env)
        );
        return json(
          {
            token: tk,
            expiresAt: exp,
            user: {
              id: user.id,
              name: user.name,
              role: m.role,
              permissions,
              companyId: c.id,
              companyName: c.name,
              companyCode: normalizedCode
            }
          },
          200,
          origin
        );
      }

      if (u.pathname.startsWith('/api/')) {
        const session = await auth(req, env);
        if (!session) return json({ error: 'غير مصرح بالدخول أو انتهت الجلسة. يرجى تسجيل الدخول أولاً.' }, 401, origin);

        if (req.method === 'GET' && u.pathname === '/api/me') {
          return json(
            {
              ok: true,
              userId: session.userId,
              companyId: session.companyId,
              role: session.role,
              permissions: session.permissions,
              exp: session.exp
            },
            200,
            origin
          );
        }

        const canManageMembers = session.role === 'owner' || Boolean(session.permissions.members);

        if (req.method === 'POST' && u.pathname === '/api/members') {
          if (!canManageMembers) return json({ error: 'لا تملك صلاحية إضافة أو إدارة أعضاء الفريق.' }, 403, origin);
          const body = await parseJsonBody(req);
          if (!body) return json({ error: 'صيغة البيانات المرسلة غير صالحة.' }, 400, origin);

          const { name, username, email, password, role = 'member', permissions } = body;
          if (!name || !username || !email || !password || String(password).length < 3 || !['manager', 'member'].includes(role)) {
            return json({ error: 'بيانات العضو غير مكتملة أو كلمة المرور أقل من 3 أحرف.' }, 400, origin);
          }
          const emailN = String(email).trim().toLowerCase();
          const userN = String(username).trim().toLowerCase();
          const existingEmail = await env.DB.prepare('SELECT id FROM users WHERE LOWER(TRIM(email))=?').bind(emailN).first();
          if (existingEmail) return json({ error: 'البريد الإلكتروني مستخدم بالفعل.' }, 409, origin);
          const existingUsername = await env.DB.prepare('SELECT id FROM users WHERE username=?').bind(userN).first();
          if (existingUsername) return json({ error: 'اسم المستخدم مستخدم بالفعل.' }, 409, origin);
          const uid = crypto.randomUUID();
          const salt = crypto.randomUUID();
          const memberPerms = normalizePermissions(permissions, role);
          await env.DB.batch([
            env.DB.prepare('INSERT INTO users(id,email,username,name,password_hash) VALUES(?,?,?,?,?)')
              .bind(uid, emailN, userN, String(name).trim(), salt + ':' + (await hash(String(password), salt))),
            env.DB.prepare(
              'INSERT INTO memberships(id,company_id,user_id,role,permissions_json) VALUES(?,?,?,?,?)'
            ).bind(crypto.randomUUID(), session.companyId, uid, role, JSON.stringify(memberPerms))
          ]);
          return json({ ok: true, id: uid, permissions: memberPerms }, 201, origin);
        }

        if (req.method === 'GET' && u.pathname === '/api/members') {
          if (!canManageMembers) return json({ error: 'لا تملك صلاحية عرض أعضاء الفريق.' }, 403, origin);
          const rows = await env.DB.prepare(
            'SELECT u.id,u.name,u.username,u.email,m.role,m.permissions_json,m.created_at FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.company_id=?'
          )
            .bind(session.companyId)
            .all();
          const formatted = (rows.results || []).map((r) => ({
            id: r.id,
            name: r.name,
            username: r.username,
            email: r.email,
            role: r.role,
            permissions: normalizePermissions(r.permissions_json, r.role),
            created_at: r.created_at
          }));
          return json(formatted, 200, origin);
        }

        if ((req.method === 'PUT' || req.method === 'PATCH') && u.pathname.startsWith('/api/members/')) {
          if (!canManageMembers) return json({ error: 'لا تملك صلاحية تعديل صلاحيات الأعضاء.' }, 403, origin);
          const targetUserId = decodeURIComponent(u.pathname.slice('/api/members/'.length)).trim();
          if (!targetUserId || targetUserId.includes('/')) return json({ error: 'معرف العضو غير صالح.' }, 400, origin);
          const target = await env.DB.prepare(
            'SELECT role, permissions_json FROM memberships WHERE company_id=? AND user_id=?'
          )
            .bind(session.companyId, targetUserId)
            .first();
          if (!target) return json({ error: 'العضو غير موجود في هذه الشركة.' }, 404, origin);
          if (target.role === 'owner' && session.role !== 'owner') {
            return json({ error: 'لا يمكن تعديل صلاحيات مالك الشركة.' }, 403, origin);
          }
          const body = await parseJsonBody(req);
          if (!body) return json({ error: 'صيغة البيانات المرسلة غير صالحة.' }, 400, origin);

          const nextRole =
            target.role === 'owner'
              ? 'owner'
              : ['manager', 'member'].includes(body.role)
                ? body.role
                : target.role;
          const mergedPerms = normalizePermissions(
            { ...normalizePermissions(target.permissions_json, target.role), ...(body.permissions || {}) },
            nextRole
          );
          await env.DB.prepare(
            'UPDATE memberships SET role=?, permissions_json=? WHERE company_id=? AND user_id=?'
          )
            .bind(nextRole, JSON.stringify(mergedPerms), session.companyId, targetUserId)
            .run();
          return json({ ok: true, userId: targetUserId, role: nextRole, permissions: mergedPerms }, 200, origin);
        }

        if (req.method === 'POST' && u.pathname === '/api/ai') {
          if (session.role !== 'owner' && !session.permissions.ai) {
            return json({ error: 'لا تملك صلاحية استخدام مساعد الذكاء الاصطناعي.' }, 403, origin);
          }
          const body = await parseJsonBody(req);
          if (!body) return json({ error: 'صيغة البيانات المرسلة غير صالحة.' }, 400, origin);

          const q = String(body.question || '').trim();
          const mode = String(body.mode || 'deep_analysis').trim();
          if (!q && !body.images?.length) return json({ error: 'يرجى كتابة سؤال أو إرفاق صورة.' }, 400, origin);

          const modeHint =
            mode === 'deep_analysis'
              ? 'المطلوب: تحليل هندسي وتشغيلي فائق الدقة والشمول، مع خطة تنفيذ عملية متكاملة وبدائل وتدرج الضوابط وأسئلة متابعة ذكية.'
              : mode === 'quick_action'
                ? 'المطلوب: خطوات تنفيذية فورية ومباشرة ودقيقة للميدان مرتبة حسب الأولوية.'
                : 'المطلوب: تحليل عملي متعمق يشمل تقييم المخاطر، البدائل الهندسية والإدارية، الافتراضات، وخطوات التنفيذ.';

          const promptText = `${modeHint}\n\nالطلب / الاستفسار:\n${q || 'حلل الصور المرفقة تحليلاً شاملاً ودقيقاً من منظور السلامة والصحة المهنية والهندسة الصناعية.'}`;

          let aiResult;
          try {
            aiResult = await runHighPrecisionAI(env, promptText, body.images || [], mode);
          } catch (aiErr) {
            if (String(aiErr?.message || '') === 'NO_AI_KEY') {
              return json(
                {
                  error: 'مفتاح الذكاء الاصطناعي غير مُعدّ بعد.',
                  message: 'أضف GEMINI_API_KEY أو OPENAI_API_KEY في إعدادات المشروع على Cloudflare (Settings -> Variables and Secrets).'
                },
                503,
                origin
              );
            }
            return json({ error: aiErr.message || 'تعذر إتمام التحليل من مزود الذكاء الاصطناعي.' }, 502, origin);
          }

          const recordId = crypto.randomUUID();
          await env.DB.prepare('INSERT INTO records(id,company_id,user_id,kind,payload) VALUES(?,?,?,?,?)')
            .bind(
              recordId,
              session.companyId,
              session.userId,
              'ai_analysis',
              JSON.stringify({
                question: q,
                mode,
                model: aiResult.modelUsed,
                answer: aiResult.answer,
                imageCount: body.images?.length || 0
              })
            )
            .run();
          return json({ id: recordId, answer: aiResult.answer, model: aiResult.modelUsed }, 200, origin);
        }

        if (req.method === 'POST' && u.pathname === '/api/records') {
          if (session.role !== 'owner' && !session.permissions.records) {
            return json({ error: 'لا تملك صلاحية إضافة السجلات.' }, 403, origin);
          }
          const body = await parseJsonBody(req);
          if (!body) return json({ error: 'صيغة البيانات المرسلة غير صالحة.' }, 400, origin);

          const id = crypto.randomUUID();
          const kind = String(body.kind || 'record').trim();
          const payload = JSON.stringify(body.payload || {});
          await env.DB.prepare('INSERT INTO records(id,company_id,user_id,kind,payload) VALUES(?,?,?,?,?)')
            .bind(id, session.companyId, session.userId, kind, payload)
            .run();
          return json({ ok: true, id }, 201, origin);
        }

        if (req.method === 'GET' && u.pathname === '/api/records') {
          if (session.role !== 'owner' && !session.permissions.records) {
            return json({ error: 'لا تملك صلاحية عرض السجلات.' }, 403, origin);
          }
          const kind = u.searchParams.get('kind');
          const rows = kind
            ? await env.DB.prepare(
                'SELECT id,kind,payload,created_at FROM records WHERE company_id=? AND kind=? ORDER BY created_at DESC LIMIT 200'
              )
                .bind(session.companyId, kind)
                .all()
            : await env.DB.prepare(
                'SELECT id,kind,payload,created_at FROM records WHERE company_id=? ORDER BY created_at DESC LIMIT 200'
              )
                .bind(session.companyId)
                .all();
          return json(rows.results || [], 200, origin);
        }

        if (req.method === 'DELETE' && u.pathname.startsWith('/api/records/')) {
          if (session.role !== 'owner' && !session.permissions.delete_records) {
            return json({ error: 'لا تملك صلاحية حذف السجلات.' }, 403, origin);
          }
          const id = decodeURIComponent(u.pathname.slice('/api/records/'.length)).trim();
          if (!id || id.includes('/')) return json({ error: 'معرف السجل غير صالح.' }, 400, origin);
          const res = await env.DB.prepare('DELETE FROM records WHERE id=? AND company_id=?')
            .bind(id, session.companyId)
            .run();
          const deleted = res.meta?.changes || 0;
          if (!deleted) return json({ error: 'السجل غير موجود أو تم حذفه مسبقاً.' }, 404, origin);
          return json({ ok: true, deleted }, 200, origin);
        }

        if (req.method === 'POST' && u.pathname === '/api/documents') {
          if (session.role !== 'owner' && !session.permissions.documents) {
            return json({ error: 'لا تملك صلاحية إضافة المستندات.' }, 403, origin);
          }
          const body = await parseJsonBody(req);
          if (!body || !body.name || !body.object_key) {
            return json({ error: 'بيانات المستند غير مكتملة.' }, 400, origin);
          }
          const id = crypto.randomUUID();
          await env.DB.prepare('INSERT INTO documents(id,company_id,user_id,name,object_key,mime,size) VALUES(?,?,?,?,?,?,?)')
            .bind(
              id,
              session.companyId,
              session.userId,
              String(body.name).trim(),
              String(body.object_key).trim(),
              String(body.mime || 'application/octet-stream'),
              Number(body.size || 0)
            )
            .run();
          return json({ ok: true, id }, 201, origin);
        }

        if (req.method === 'GET' && u.pathname === '/api/documents') {
          if (session.role !== 'owner' && !session.permissions.documents) {
            return json({ error: 'لا تملك صلاحية عرض المستندات.' }, 403, origin);
          }
          const rows = await env.DB.prepare(
            'SELECT id,name,object_key,mime,size,created_at FROM documents WHERE company_id=? ORDER BY created_at DESC LIMIT 200'
          )
            .bind(session.companyId)
            .all();
          return json(rows.results || [], 200, origin);
        }

        return json({ error: 'المسار المطلوب غير موجود.' }, 404, origin);
      }

      if (env.ASSETS) {
        return env.ASSETS.fetch(req);
      }

      return json({ error: 'Not found' }, 404, origin);
    } catch (e) {
      const errText = String(e?.message || e || '');
      if (/UNIQUE/i.test(errText)) {
        return json({ error: 'البريد الإلكتروني أو اسم المستخدم مستخدم بالفعل.' }, 409, origin);
      }
      return json({ error: 'خطأ في الخادم', message: errText }, 500, origin);
    }
  }
};
