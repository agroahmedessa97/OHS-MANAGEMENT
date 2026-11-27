const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };
const OTP_TTL_SECONDS = 120;
const RESET_TTL_SECONDS = 300;

function reply(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function randomDigits(length = 6) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, n => String(n % 10)).join("");
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

async function readJson(request) {
  try { return await request.json(); } catch { return null; }
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST") return reply({ ok: false, error: "Method not allowed" }, 405);
  if (!env.OTP_KV) return reply({ ok: false, error: "OTP_KV binding is missing" }, 500);

  const origin = request.headers.get("Origin");
  if (origin && origin !== url.origin) return reply({ ok: false, error: "Cross-origin request blocked" }, 403);

  const body = await readJson(request);
  if (!body) return reply({ ok: false, error: "Invalid JSON" }, 400);

  if (url.pathname === "/api/assistant") {
    if (!env.GEMINI_API_KEY) return reply({ ok: false, error: "GEMINI_API_KEY secret is not configured" }, 500);
    const question = String(body.question || "").trim();
    const context = String(body.context || "").slice(0, 12000);
    if (!question || question.length > 5000) return reply({ ok: false, error: "السؤال فارغ أو أطول من المسموح." }, 400);
    const geminiResponse = await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + encodeURIComponent(env.GEMINI_API_KEY), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: context + "\n\nسؤال المستخدم: " + question }] }] })
    }).catch(() => null);
    if (!geminiResponse) return reply({ ok: false, error: "تعذر الاتصال بخدمة المساعد الذكي." }, 502);
    const geminiData = await geminiResponse.json().catch(() => ({}));
    if (!geminiResponse.ok) return reply({ ok: false, error: geminiData.error?.message || "فشل طلب المساعد الذكي." }, 502);
    const answer = geminiData?.candidates?.[0]?.content?.parts?.[0]?.text || "لم تصل إجابة من المساعد.";
    return reply({ ok: true, text: answer });
  }

  const email = normalizeEmail(body.email);
  if (!validEmail(email)) return reply({ ok: false, error: "يرجى إدخال بريد إلكتروني صحيح." }, 400);
  const emailHash = await sha256(email);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  if (url.pathname === "/api/send-otp") {
    if (!env.RESEND_API_KEY || !env.FROM_EMAIL) {
      return reply({ ok: false, error: "إعدادات Resend غير مكتملة على Cloudflare Worker." }, 500);
    }
    const emailLimitKey = `limit:email:${emailHash}`;
    const ipLimitKey = `limit:ip:${await sha256(ip)}`;
    if (await env.OTP_KV.get(emailLimitKey)) {
      return reply({ ok: false, error: "تم إرسال كود إلى هذا البريد مؤخراً. انتظر دقيقة ثم حاول مجدداً." }, 429);
    }
    const ipCount = Number(await env.OTP_KV.get(ipLimitKey) || "0");
    if (ipCount >= 5) return reply({ ok: false, error: "تم تجاوز عدد طلبات الإرسال المسموح. حاول بعد 10 دقائق." }, 429);

    const code = randomDigits(6);
    await env.OTP_KV.put(`otp:${emailHash}`, JSON.stringify({ hash: await sha256(code), attempts: 0 }), { expirationTtl: OTP_TTL_SECONDS });
    await env.OTP_KV.put(emailLimitKey, "1", { expirationTtl: 60 });
    await env.OTP_KV.put(ipLimitKey, String(ipCount + 1), { expirationTtl: 600 });

    const resendResponse = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: env.FROM_EMAIL,
        to: [email],
        subject: "كود استعادة كلمة مرور نظام السلامة والصحة المهنية",
        html: `<div dir="rtl" style="font-family:Arial,sans-serif"><h2>كود التحقق</h2><p>كود استعادة كلمة المرور هو:</p><div style="font-size:28px;font-weight:bold;letter-spacing:6px">${code}</div><p>تنتهي صلاحية الكود خلال دقيقتين.</p></div>`
      })
    }).catch(() => null);

    if (!resendResponse || !resendResponse.ok) {
      await env.OTP_KV.delete(`otp:${emailHash}`);
      const details = resendResponse ? await resendResponse.json().catch(() => ({})) : {};
      return reply({ ok: false, error: details.message || "تعذر الاتصال بخدمة البريد Resend." }, 502);
    }
    return reply({ ok: true, expiresIn: OTP_TTL_SECONDS });
  }

  if (url.pathname === "/api/verify-otp") {
    const code = String(body.code || "").trim();
    if (!/^\d{6}$/.test(code)) return reply({ ok: false, error: "كود التحقق يجب أن يتكون من 6 أرقام." }, 400);
    const key = `otp:${emailHash}`;
    const record = await env.OTP_KV.get(key, "json");
    if (!record) return reply({ ok: false, error: "الكود غير موجود أو انتهت صلاحيته. اطلب كوداً جديداً." }, 400);
    if (record.attempts >= 5) {
      await env.OTP_KV.delete(key);
      return reply({ ok: false, error: "تم إلغاء الكود بعد 5 محاولات خاطئة. اطلب كوداً جديداً." }, 429);
    }
    if ((await sha256(code)) !== record.hash) {
      record.attempts += 1;
      await env.OTP_KV.put(key, JSON.stringify(record), { expirationTtl: OTP_TTL_SECONDS });
      return reply({ ok: false, error: `كود التحقق غير صحيح. المحاولات المتبقية: ${5 - record.attempts}.` }, 400);
    }
    await env.OTP_KV.delete(key);
    const resetToken = randomToken();
    await env.OTP_KV.put(`reset:${emailHash}`, await sha256(resetToken), { expirationTtl: RESET_TTL_SECONDS });
    return reply({ ok: true, resetToken, expiresIn: RESET_TTL_SECONDS });
  }

  if (url.pathname === "/api/consume-reset") {
    const token = String(body.resetToken || "");
    if (!/^[a-f0-9]{64}$/.test(token)) return reply({ ok: false, error: "جلسة الاستعادة غير صالحة." }, 400);
    const key = `reset:${emailHash}`;
    const storedHash = await env.OTP_KV.get(key);
    if (!storedHash || storedHash !== await sha256(token)) {
      return reply({ ok: false, error: "انتهت جلسة الاستعادة أو تم استخدامها. اطلب كوداً جديداً." }, 400);
    }
    await env.OTP_KV.delete(key);
    return reply({ ok: true });
  }

  return reply({ ok: false, error: "Not found" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return handleApi(request, env);
    if (!env.ASSETS) return reply({ ok: false, error: "Static Assets binding ASSETS is missing" }, 500);
    const response = await env.ASSETS.fetch(request);
    const headers = new Headers(response.headers);
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    headers.set("X-Frame-Options", "DENY");
    if (url.pathname === "/" || url.pathname.endsWith(".html")) headers.set("Cache-Control", "no-store");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  }
};
