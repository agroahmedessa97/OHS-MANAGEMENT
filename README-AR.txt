حزمة نشر نظام إدارة السلامة والصحة المهنية على Cloudflare Workers

محتويات الحزمة:
- public/index.html : واجهة النظام بعد ربط الاستعادة بمسارات API على نفس النطاق.
- src/worker.js : Worker لخدمة الموقع وإرسال/التحقق من OTP باستخدام Resend وKV.
- wrangler.toml : إعداد نشر Worker مع Static Assets وربط KV.

قبل النشر:
1) من Cloudflare Dashboard > Workers & Pages > KV، أنشئ Namespace باسم OHS_OTP.
2) انسخ Namespace ID وضعه مكان REPLACE_WITH_YOUR_KV_NAMESPACE_ID في wrangler.toml.
3) ثبّت Node.js على الكمبيوتر ثم نفّذ داخل مجلد الحزمة:
   npm install -D wrangler
   npx wrangler login
   npx wrangler secret put RESEND_API_KEY
   ثم أدخل مفتاح Resend الجديد عند الطلب.
4) أضف متغير FROM_EMAIL في إعدادات Worker (Variables) بقيمة بريد مرسل موثّق داخل Resend.
5) أضف Secret باسم GEMINI_API_KEY بمفتاح Gemini جديد (لا تضع المفتاح في HTML).
6) انشر:
   npx wrangler deploy
7) افتح رابط Worker المنشور، مثل https://ohs-management.<اسم-حسابك>.workers.dev
   لا تفتح ملف HTML من Downloads أو content://.

ملاحظات مهمة:
- لا تضع مفتاح Resend أو Gemini داخل HTML أو JavaScript. احتفظ بهما كـ Secrets في Worker فقط. تم تحويل طلبات مساعد Gemini إلى المسار /api/assistant.
- واجهة النظام الحالية تحتفظ بحسابات المديرين والأعضاء في localStorage على الجهاز/المتصفح. لذلك تغيير كلمة المرور عبر الاستعادة يغيّر السجل المحلي في المتصفح الذي نفّذ العملية فقط؛ لا توجد قاعدة بيانات مركزية متزامنة بين الأجهزة حتى الآن.
- تم نقل إنشاء كود OTP والتحقق منه إلى Worker وتخزين بصمة الكود في KV، مع صلاحية دقيقتين، 5 محاولات، ورمز استعادة لمرة واحدة.
- قبل الاستخدام الفعلي متعدد الأجهزة أو لبيانات تشغيلية حساسة، يلزم نقل حسابات المستخدمين والجلسات إلى قاعدة بيانات مركزية مثل Cloudflare D1 وتنفيذ المصادقة على الخادم. هذه الحزمة لا تنفذ ترحيل بيانات الحسابات إلى D1.
- ألغِ أي مفاتيح Resend أو Gemini كانت موجودة سابقاً داخل ملفات HTML المنشورة وأنشئ مفاتيح جديدة؛ اعتبر المفتاحين السابقين مكشوفين.
