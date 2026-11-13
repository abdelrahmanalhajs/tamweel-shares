# Feature status

Generated from the in-app page (#/features). Three groups:

## ✅ Works (real code, runs on the Node server **and** in the browser demo)
- Accounts, roles, secure login (scrypt + sessions)  
  حسابات وأدوار وتسجيل دخول آمن (scrypt + جلسات)
- KYC & document upload  
  التحقق من الهوية KYC ورفع المستندات
- Funding applications, admin review, risk rating  
  طلبات التمويل ومراجعة الإدارة وتقييم المخاطر
- Search, filters, project details  
  البحث والفلترة وصفحة تفاصيل المشروع
- Investment calculator (4 scenarios)  
  حاسبة الاستثمار (٤ سيناريوهات)
- Wallet & admin-approved withdrawals  
  المحفظة والسحب بموافقة الإدارة
- Financial analyzer, explainable rating, alerts (rules)  
  المحلل المالي والتقييم المفسَّر والتنبيهات (قواعد)
- Fraud/anomaly detection (rules)  
  كشف التناقضات/التلاعب (قواعد)
- Indicative valuation  
  التقدير الاسترشادي للقيمة
- Expansion simulator  
  محاكي التوسع
- Digital contracts & document vault  
  العقود الإلكترونية وخزنة المستندات
- Monthly reports & in-app notifications  
  التقارير الشهرية والإشعارات داخل المنصة
- Q&A, updates, polls & voting  
  الأسئلة والأجوبة والتحديثات والتصويت
- Follow, compare, smart recommendations  
  متابعة المشروع والمقارنة والتوصيات الذكية
- Founder reputation  
  سجل صاحب المشروع (Founder reputation)
- Exits & resale market with ownership transfer  
  السوق الثانوي والتخارج ونقل الحصص
- Two-factor login (TOTP)  
  مصادقة ثنائية (TOTP)
- Academy & investor-protection/complaints centre  
  الأكاديمية ومركز الشكاوى وحماية المستثمر
- Admin dashboard & audit log  
  لوحة الإدارة وسجل المراجعة (Audit log)
- Portfolio analysis  
  تحليل المحفظة (القطاع/المخاطرة/التركّز)

## 🟠 Simulated in the browser demo — backend still to be built for the Render deployment
These run on the GitHub Pages demo (localStorage). On a real server they need API endpoints + database tables (the UI and rules are already written, so porting is mostly mirroring `staticApi` in `server.js`).
- Project timeline / milestones  
  مراحل تنفيذ المشروع (Timeline)
- Use-of-funds tracking vs plan  
  متابعة استخدام التمويل ومقارنته بالخطة
- Live project photos  
  صور ومتابعة من أرض الواقع
- Owner meetings (scheduling + RSVP)  
  لقاءات مباشرة مع أصحاب المشروعات (جدولة)
- Announcements & investor discussion forum  
  الإعلانات المهمة ومجتمع نقاش المستثمرين
- Distribution statements  
  كشوف التوزيعات للمستثمر
- Risk-management console & investor alerts  
  لوحة إدارة المخاطر وإرسال تنبيهات للمستثمرين
- Overdue reports/milestones & fund-plan breaches  
  متابعة التأخر في التقارير والمراحل ومخالفة خطة التمويل
- Revenue management (study/success/management fees) & reports  
  إدارة الإيرادات (رسوم الدراسة/النجاح/المتابعة) والتقارير
- Escrow ledger (hold/release simulation)  
  حساب الضمان Escrow (محاكاة الاحتجاز والتحويل)
- Admin edit opportunity & close subscriptions  
  تعديل الفرصة وإغلاق الاكتتاب من الإدارة
- CSV export & JSON backup  
  تصدير CSV ونسخة احتياطية JSON
- AI assistant (rule-based on platform data)  
  المساعد الذكي (قواعد من بيانات المنصة)
- AI document reader (demo figures)  
  قراءة المستندات بالذكاء الاصطناعي (أرقام تجريبية)
- Failed-login log & privacy consent  
  سجل محاولات الدخول الفاشلة وموافقة الخصوصية

## ⚪ Needs a third party, a licence or infrastructure (cannot be built inside the repo)
- Real LLM assistant — needs API key  
  المساعد الذكي الحقيقي (LLM) — يحتاج مفتاح API
- Real OCR/LLM document reading — needs API key  
  قراءة المستندات الحقيقية OCR/LLM — يحتاج مفتاح API
- SMS phone OTP  
  رمز تحقق SMS (OTP) للهاتف
- Qualified e-signature  
  توقيع إلكتروني معتمد قانونيًا
- Real payment gateway & bank transfers  
  بوابة دفع حقيقية وإيداع/سحب بنكي
- Licensed escrow & custody  
  ضمان وحفظ أموال لدى جهة مرخّصة (Escrow & Custody)
- Automated ID / commercial-register verification  
  التحقق الآلي من الهوية والسجل التجاري من جهات رسمية
- Email / SMS / push notifications  
  إشعارات البريد/الرسائل (Email/SMS/Push)
- Live video meetings (3rd-party)  
  اجتماعات الفيديو المباشرة (منصة طرف ثالث)
- Encryption at rest, automated backups, secure file storage  
  تشفير البيانات المخزنة ونسخ احتياطية تلقائية وتخزين ملفات آمن
- Owner subscriptions (billing)  
  اشتراكات أصحاب المشروعات (فوترة)
- Regulatory licence (FRA) & legal compliance  
  ترخيص الهيئة العامة للرقابة المالية والامتثال القانوني
- Data-protection law compliance (legal review)  
  الالتزام بقوانين حماية البيانات (مراجعة قانونية)

> Selling shares to the public needs regulatory licensing (e.g. FRA in Egypt) and licensed escrow/payments before real money moves. Nothing here is legal advice.
