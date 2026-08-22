import express from "express";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "node:path";
import crypto from "node:crypto";

const { Pool } = pg;
const app = express();

const PORT = Number(process.env.PORT) || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET) {
  console.error("ERROR: JWT_SECRET is missing.");
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on("error", (err) => console.error("Unexpected PostgreSQL error:", err));

app.use(express.json({ limit: "3mb" }));
app.use(express.urlencoded({ extended: true, limit: "3mb" }));

async function db(sql, params = []) {
  return pool.query(sql, params);
}

function tokenFor(user, jti) { return jwt.sign({ id:user.id, role:user.role, jti }, JWT_SECRET, {expiresIn:"7d"}); }

async function createSession(user, deviceId, deviceName="") {
  const d=String(deviceId||"").trim();
  if(!d || d.length>200) throw Object.assign(new Error("معرّف الجهاز غير صالح"),{status:400});
  const c=await pool.connect();
  try {
    await c.query("BEGIN");
    const exists=(await c.query("SELECT id FROM user_devices WHERE user_id=$1 AND device_id=$2 FOR UPDATE",[user.id,d])).rows[0];
    if(!exists){
      const count=Number((await c.query("SELECT COUNT(*)::int AS n FROM user_devices WHERE user_id=$1",[user.id])).rows[0].n);
      if(count>=2){ await c.query("ROLLBACK"); throw Object.assign(new Error("تم الوصول إلى الحد الأقصى وهو جهازان لهذا الحساب. سجّل الخروج من أحد الأجهزة أولًا."),{status:409}); }
      await c.query("INSERT INTO user_devices(user_id,device_id,device_name) VALUES($1,$2,$3)",[user.id,d,String(deviceName||"").slice(0,200)]);
    } else await c.query("UPDATE user_devices SET last_seen_at=NOW(),device_name=COALESCE(NULLIF($3,''),device_name) WHERE user_id=$1 AND device_id=$2",[user.id,d,String(deviceName||"").slice(0,200)]);
    await c.query("UPDATE user_sessions SET active=false WHERE user_id=$1",[user.id]);
    const jti=crypto.randomUUID();
    await c.query("INSERT INTO user_sessions(user_id,device_id,jti,active) VALUES($1,$2,$3,true)",[user.id,d,jti]);
    await c.query("COMMIT"); return tokenFor(user,jti);
  } catch(e){ try{await c.query("ROLLBACK")}catch{}; throw e; } finally{c.release();}
}

async function invalidateSession(jti){ if(jti) await db("UPDATE user_sessions SET active=false WHERE jti=$1",[jti]); }

function auth(req,res,next){
  (async()=>{try{const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))return res.status(401).json({error:"تسجيل الدخول مطلوب"});const payload=jwt.verify(h.slice(7),JWT_SECRET);const r=await db("SELECT active FROM user_sessions WHERE jti=$1 AND user_id=$2",[payload.jti,payload.id]);if(!r.rows[0]?.active)return res.status(401).json({error:"تم إنهاء جلسة الدخول الحالية لأن الحساب سجّل الدخول من جهاز آخر."});req.user=payload;await db("UPDATE user_sessions SET last_seen_at=NOW() WHERE jti=$1",[payload.jti]);next();}catch{res.status(401).json({error:"جلسة الدخول غير صالحة"});}})();
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ error: "غير مصرح" });
  }
  next();
}

function publicUser(row) {
  const expires = row.subscription_expires_at ? new Date(row.subscription_expires_at) : null;
  const active = !!row.subscribed && (!expires || expires.getTime() > Date.now());
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    wallet_balance: Number(row.wallet_balance || 0),
    subscribed: active,
    subscription_started_at: row.subscription_started_at || null,
    subscription_expires_at: row.subscription_expires_at || null
  };
}

function subscriptionActive(row) {
  return !!row?.subscribed && (!row.subscription_expires_at || new Date(row.subscription_expires_at).getTime() > Date.now());
}

/* =========================================================
   DATABASE
   No schema.sql is required. The schema is created here.
========================================================= */

async function initDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS site_settings (
      id INTEGER PRIMARY KEY DEFAULT 1,
      site_name TEXT NOT NULL DEFAULT 'StudyMedSmart',
      tagline TEXT NOT NULL DEFAULT 'منصة تعليمية طبية',
      subscription_price NUMERIC(12,2) NOT NULL DEFAULT 100,
      subscription_weeks INTEGER NOT NULL DEFAULT 25,
      hero_title TEXT NOT NULL DEFAULT 'ابدأ رحلتك الطبية بثقة',
      hero_text TEXT NOT NULL DEFAULT 'تعلم أساسيات المجال الطبي في مكان واحد.',
      hero_image TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS site_social_links (id BIGSERIAL PRIMARY KEY,platform TEXT NOT NULL UNIQUE,url TEXT NOT NULL DEFAULT '',sort_order INTEGER NOT NULL DEFAULT 0,is_active BOOLEAN NOT NULL DEFAULT TRUE,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());

    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      wallet_balance NUMERIC(12,2) NOT NULL DEFAULT 0,
      subscribed BOOLEAN NOT NULL DEFAULT FALSE,
      subscription_started_at TIMESTAMPTZ,
      subscription_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_devices (id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,device_id TEXT NOT NULL,device_name TEXT NOT NULL DEFAULT '',last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),UNIQUE(user_id,device_id));

    CREATE TABLE IF NOT EXISTS user_sessions (id BIGSERIAL PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,device_id TEXT NOT NULL,jti TEXT NOT NULL UNIQUE,active BOOLEAN NOT NULL DEFAULT TRUE,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW());

    CREATE TABLE IF NOT EXISTS courses (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL DEFAULT '',
      image_url TEXT NOT NULL DEFAULT '',
      sort_order INTEGER NOT NULL DEFAULT 0,
      is_published BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS lessons (
      id BIGSERIAL PRIMARY KEY,
      course_id BIGINT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      video_url TEXT NOT NULL DEFAULT '',
      pdf_url TEXT NOT NULL DEFAULT '',
      sort_order INTEGER NOT NULL DEFAULT 0,
      is_published BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS quizzes (
      id BIGSERIAL PRIMARY KEY,
      lesson_id BIGINT NOT NULL UNIQUE REFERENCES lessons(id) ON DELETE CASCADE,
      passing_score INTEGER NOT NULL DEFAULT 50
    );

    CREATE TABLE IF NOT EXISTS quiz_questions (
      id BIGSERIAL PRIMARY KEY,
      quiz_id BIGINT NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
      question TEXT NOT NULL DEFAULT '',
      option_a TEXT NOT NULL DEFAULT '',
      option_b TEXT NOT NULL DEFAULT '',
      option_c TEXT NOT NULL DEFAULT '',
      option_d TEXT NOT NULL DEFAULT '',
      correct_option TEXT NOT NULL DEFAULT 'A',
      explanation TEXT NOT NULL DEFAULT '',
      sort_order INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS lesson_progress (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      lesson_id BIGINT NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
      completed BOOLEAN NOT NULL DEFAULT FALSE,
      score INTEGER,
      attempts INTEGER NOT NULL DEFAULT 0,
      last_attempt_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      quiz_result JSONB,
      UNIQUE(user_id, lesson_id)
    );

    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL,
      type TEXT NOT NULL,
      note TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    INSERT INTO site_settings (id)
    VALUES (1)
    ON CONFLICT (id) DO NOTHING;
  `);

  await db(`UPDATE site_settings SET subscription_price=100 WHERE id=1 AND COALESCE(subscription_price,0)=0`);
  await db(`ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS hero_image TEXT NOT NULL DEFAULT ''`);
  await db(`ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS subscription_weeks INTEGER NOT NULL DEFAULT 25`);
  await db(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_started_at TIMESTAMPTZ`);
  await db(`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_expires_at TIMESTAMPTZ`);
  await db(`UPDATE site_settings SET subscription_weeks=25 WHERE id=1 AND (subscription_weeks IS NULL OR subscription_weeks<=0)`);
  await db(`UPDATE users SET subscription_started_at=COALESCE(subscription_started_at,NOW()), subscription_expires_at=COALESCE(subscription_expires_at,NOW()+INTERVAL '25 weeks') WHERE subscribed=true AND subscription_expires_at IS NULL`);
  await db(`ALTER TABLE lesson_progress ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  await db(`ALTER TABLE lesson_progress ADD COLUMN IF NOT EXISTS quiz_result JSONB`);

  const defaultCourses = [
    ["المصطلحات الطبية والمهارات الأساسية","medical-terminology","Medical Terminology والمهارات الطبية الأساسية والمفاهيم التي يحتاجها الطالب في بداية دراسة الطب.","🩺",1],
    ["أساسيات أجهزة الجسم","body-systems","أساسيات أجهزة جسم الإنسان: الدوري والتنفسـي والهضمي والعصبي وغيرها.","🫀",2],
    ["دورة الإسعافات الأولية","first-aid","أساسيات الإسعافات الأولية والتعامل الأولي الآمن مع الحالات المختلفة.","⛑️",3],
    ["التأسيس في المواد الطبية","medical-foundations","مدخل مبسط إلى Anatomy وPhysiology وHistology وBiochemistry وImmunology وGenetics.","🔬",4],
    ["نصائح المذاكرة","study-skills","تنظيم المذاكرة وإدارة الوقت والتعامل مع المواد الطبية وبناء طريقة دراسة مناسبة.","📚",5],
    ["التخطيط المستقبلي في الكليات الطبية","medical-future","التخطيط للمستقبل وفهم طبيعة الدراسة الطبية واختيار المسار والاستعداد للحياة الأكاديمية والمهنية.","🎓",6]
  ];
  for (const [title,slug,description,image_url,sort_order] of defaultCourses) {
    await db(`INSERT INTO courses(title,slug,description,image_url,sort_order,is_published) VALUES($1,$2,$3,$4,$5,true) ON CONFLICT(slug) DO UPDATE SET title=EXCLUDED.title,description=EXCLUDED.description,image_url=EXCLUDED.image_url,sort_order=EXCLUDED.sort_order`, [title,slug,description,image_url,sort_order]);
  }

  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminEmail && adminPassword) {
    const email = String(adminEmail).trim().toLowerCase();
    const hash = await bcrypt.hash(String(adminPassword), 10);

    await db(`
      INSERT INTO users (name, email, password_hash, role)
      VALUES ($1, $2, $3, 'admin')
      ON CONFLICT (email)
      DO UPDATE SET role='admin', password_hash=EXCLUDED.password_hash
    `, ["Administrator", email, hash]);

    console.log(`Admin account ready: ${email}`);
  }

  console.log("Database initialization completed.");
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/healthz", async (req, res) => {
  try {
    await db("SELECT 1");
    res.json({ ok: true, database: true });
  } catch (e) {
    res.status(503).json({ ok: false, database: false, error: e.message });
  }
});

/* =========================================================
   PUBLIC SETTINGS / COURSES
========================================================= */

app.get("/api/settings", async (req, res) => {
  try {
    const r = await db("SELECT * FROM site_settings WHERE id=1");
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر تحميل إعدادات الموقع" });
  }
});

app.get("/api/courses", async (req, res) => {
  try {
    const r = await db(`
      SELECT * FROM courses
      WHERE is_published=true
        AND slug IN ('medical-terminology','body-systems','first-aid','medical-foundations','study-skills','medical-future')
      ORDER BY sort_order ASC, id ASC
    `);
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر تحميل الكورسات" });
  }
});

app.get("/api/courses/:slug", async (req, res) => {
  try {
    const c = await db(`
      SELECT * FROM courses
      WHERE slug=$1 AND is_published=true
    `, [req.params.slug]);

    if (!c.rows[0]) return res.status(404).json({ error: "الكورس غير موجود" });

    const course = c.rows[0];

    const l = await db(`
      SELECT
        l.id, l.course_id, l.title, l.description,
        (l.video_url <> '') AS has_video,
        (l.pdf_url <> '') AS has_pdf,
        l.sort_order, l.is_published,
        q.id AS quiz_id, q.passing_score
      FROM lessons l
      LEFT JOIN quizzes q ON q.lesson_id=l.id
      WHERE l.course_id=$1 AND l.is_published=true
      ORDER BY l.sort_order ASC, l.id ASC
    `, [course.id]);

    res.json({ ...course, lessons: l.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر تحميل الكورس" });
  }
});

/* =========================================================
   AUTH
========================================================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({ error: "جميع البيانات مطلوبة" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "كلمة المرور يجب أن تكون 6 أحرف على الأقل" });
    }

    const hash = await bcrypt.hash(password, 10);

    const r = await db(`
      INSERT INTO users (name,email,password_hash)
      VALUES ($1,$2,$3)
      RETURNING id,name,email,role,wallet_balance,subscribed
    `, [name, email, hash]);

    const user = r.rows[0];
    const deviceId=String(req.body.device_id||""); const deviceName=String(req.body.device_name||""); const token=await createSession(user,deviceId,deviceName);
    res.status(201).json({ user: publicUser(user), token });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "البريد الإلكتروني مستخدم بالفعل" });
    console.error(e);
    res.status(500).json({ error: "تعذر إنشاء الحساب" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const r = await db("SELECT * FROM users WHERE email=$1", [email]);
    const user = r.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "البريد أو كلمة المرور غير صحيحة" });
    }

    const deviceId=String(req.body.device_id||""); const deviceName=String(req.body.device_name||""); const token=await createSession(user,deviceId,deviceName);
    res.json({ user: publicUser(user), token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "حدث خطأ أثناء تسجيل الدخول" });
  }
});

app.get("/api/me", auth, async (req, res) => {
  try {
    const r = await db(`
      SELECT id,name,email,role,wallet_balance,subscribed
      FROM users WHERE id=$1
    `, [req.user.id]);

    if (!r.rows[0]) return res.status(404).json({ error: "المستخدم غير موجود" });
    res.json(publicUser(r.rows[0]));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر تحميل بيانات المستخدم" });
  }
});

/* =========================================================
   LESSON / QUIZ
========================================================= */

app.get("/api/courses/:slug/progress", auth, async (req,res)=>{try{const c=(await db("SELECT id FROM courses WHERE slug=$1",[req.params.slug])).rows[0];if(!c)return res.status(404).json({error:"الكورس غير موجود"});const r=(await db("SELECT l.id,lp.completed,lp.score FROM lessons l LEFT JOIN lesson_progress lp ON lp.lesson_id=l.id AND lp.user_id=$1 WHERE l.course_id=$2 AND l.is_published=true",[req.user.id,c.id])).rows;const scores=r.filter(x=>x.score!==null).map(x=>Number(x.score));res.json({totalLessons:r.length,completedLessons:r.filter(x=>x.completed).length,percent:r.length?Math.round(r.filter(x=>x.completed).length/r.length*100):0,averageScore:scores.length?Math.round(scores.reduce((a,b)=>a+b,0)/scores.length):0});}catch(e){res.status(500).json({error:"تعذر تحميل تقدم الكورس"});}});

app.get("/api/courses/:slug/lessons/:lessonId", auth, async (req, res) => {
  try {
    const r = await db(`
      SELECT l.*, c.slug, c.title AS course_title,
             q.id AS quiz_id, q.passing_score
      FROM lessons l
      JOIN courses c ON c.id=l.course_id
      LEFT JOIN quizzes q ON q.lesson_id=l.id
      WHERE c.slug=$1 AND l.id=$2
        AND l.is_published=true AND c.is_published=true
    `, [req.params.slug, req.params.lessonId]);

    if (!r.rows[0]) return res.status(404).json({ error: "الدرس غير موجود" });

    const user = await db("SELECT subscribed,subscription_expires_at FROM users WHERE id=$1", [req.user.id]);
    const subscribed = subscriptionActive(user.rows[0]);
    if (!subscribed) {
      return res.status(402).json({
        subscribed: false,
        locked: true,
        message: "يجب عليك الاشتراك في StudyMedSmart للوصول إلى محتوى هذا الكورس."
      });
    }

    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر تحميل الدرس" });
  }
});

app.get("/api/lessons/:lessonId/quiz", auth, async (req,res)=>{try{const u=(await db("SELECT subscribed,subscription_expires_at FROM users WHERE id=$1",[req.user.id])).rows[0];if(!subscriptionActive(u))return res.status(402).json({locked:true,subscribed:false,message:"يجب عليك الاشتراك في StudyMedSmart للوصول إلى الاختبار."});const qr=(await db("SELECT * FROM quizzes WHERE lesson_id=$1",[req.params.lessonId])).rows[0];if(!qr)return res.status(404).json({error:"لا يوجد اختبار لهذا الدرس"});const attempted=(await db("SELECT completed,score,attempts,quiz_result FROM lesson_progress WHERE user_id=$1 AND lesson_id=$2 AND attempts>0",[req.user.id,req.params.lessonId])).rows[0];const qs=(await db("SELECT id,question,option_a,option_b,option_c,option_d,sort_order FROM quiz_questions WHERE quiz_id=$1 ORDER BY sort_order,id",[qr.id])).rows;res.json({...qr,questions:qs,attempted:!!attempted,attempt:attempted?{completed:attempted.completed,score:attempted.score,attempts:attempted.attempts}:null,previous_result:attempted?.quiz_result||null});}catch(e){res.status(500).json({error:"تعذر تحميل الاختبار"});}});

app.post("/api/lessons/:lessonId/quiz/submit", auth, async (req,res)=>{const client=await pool.connect();try{await client.query("BEGIN");const u=(await client.query("SELECT subscribed,subscription_expires_at FROM users WHERE id=$1",[req.user.id])).rows[0];if(!u?.subscribed){await client.query("ROLLBACK");return res.status(402).json({locked:true,subscribed:false,message:"يجب عليك الاشتراك في StudyMedSmart للوصول إلى الاختبار."})}const prev=(await client.query("SELECT attempts FROM lesson_progress WHERE user_id=$1 AND lesson_id=$2 FOR UPDATE",[req.user.id,req.params.lessonId])).rows[0];if(prev?.attempts>0){await client.query("ROLLBACK");return res.status(409).json({error:"لقد أكملت محاولة هذا الاختبار بالفعل ولا يمكن إعادته.",attempted:true})}const qr=(await client.query("SELECT * FROM quizzes WHERE lesson_id=$1",[req.params.lessonId])).rows[0];if(!qr){await client.query("ROLLBACK");return res.status(404).json({error:"لا يوجد اختبار لهذا الدرس"})}const questions=(await client.query("SELECT * FROM quiz_questions WHERE quiz_id=$1 ORDER BY sort_order,id",[qr.id])).rows,answers=req.body.answers||{};let correct=0;const results=questions.map(q=>{const selected=String(answers[q.id]||"").toUpperCase(),co=String(q.correct_option||"").toUpperCase(),ok=selected===co;if(ok)correct++;return{id:q.id,selected,correct_option:co,explanation:q.explanation,correct:ok}});const total=questions.length,score=total?Math.round(correct/total*100):0,passed=score>=Number(qr.passing_score);const result={score,passed,passing_score:Number(qr.passing_score),total,correct,results};await client.query("INSERT INTO lesson_progress(user_id,lesson_id,completed,score,attempts,last_attempt_at,updated_at,quiz_result) VALUES($1,$2,$3,$4,1,NOW(),NOW(),$5::jsonb) ON CONFLICT(user_id,lesson_id) DO UPDATE SET completed=EXCLUDED.completed,score=EXCLUDED.score,attempts=1,last_attempt_at=NOW(),updated_at=NOW(),quiz_result=EXCLUDED.quiz_result",[req.user.id,req.params.lessonId,passed,score,JSON.stringify(result)]);await client.query("COMMIT");res.json({...result,attempted:true});}catch(e){try{await client.query("ROLLBACK")}catch{}res.status(500).json({error:"تعذر تصحيح الاختبار"})}finally{client.release()}});

/* =========================================================
   LESSON COMPLETION
========================================================= */

app.post("/api/lessons/:lessonId/view", auth, async (req,res) => {
  try {
    const u = (await db("SELECT subscribed,subscription_expires_at FROM users WHERE id=$1", [req.user.id])).rows[0];
    if (!u) return res.status(404).json({error:"المستخدم غير موجود"});
    if (!u.subscribed) return res.status(402).json({locked:true,subscribed:false,message:"يجب عليك الاشتراك في StudyMedSmart للوصول إلى محتوى هذا الكورس."});
    const lesson = (await db("SELECT id FROM lessons WHERE id=$1 AND is_published=true", [req.params.lessonId])).rows[0];
    if (!lesson) return res.status(404).json({error:"الدرس غير موجود"});
    await db(`INSERT INTO lesson_progress(user_id,lesson_id,completed,score,attempts,last_attempt_at,updated_at)
      VALUES($1,$2,false,NULL,0,NULL,NOW())
      ON CONFLICT(user_id,lesson_id) DO UPDATE SET updated_at=NOW()`,[req.user.id,req.params.lessonId]);
    res.json({ok:true});
  } catch(e) { console.error(e); res.status(500).json({error:"تعذر حفظ آخر درس تم فتحه"}); }
});

app.post("/api/lessons/:lessonId/complete", auth, async (req, res) => {
  try {
    const lessonId = Number(req.params.lessonId);
    if (!Number.isInteger(lessonId) || lessonId <= 0) return res.status(400).json({ error: "معرف الدرس غير صحيح" });
    const u = await db("SELECT subscribed,subscription_expires_at FROM users WHERE id=$1", [req.user.id]);
    if (!u.rows[0]) return res.status(404).json({ error: "المستخدم غير موجود" });
    if (!subscriptionActive(u.rows[0])) return res.status(402).json({ locked:true, subscribed:false, message:"يجب عليك الاشتراك في StudyMedSmart للوصول إلى محتوى هذا الكورس." });
    const lesson = await db("SELECT id FROM lessons WHERE id=$1 AND is_published=true", [lessonId]);
    if (!lesson.rows[0]) return res.status(404).json({ error:"الدرس غير موجود" });
    await db(`
      INSERT INTO lesson_progress(user_id,lesson_id,completed,score,attempts,last_attempt_at)
      VALUES($1,$2,true,NULL,0,NOW())
      ON CONFLICT(user_id,lesson_id) DO UPDATE SET completed=true, updated_at=NOW()
    `, [req.user.id, lessonId]);
    res.json({ ok:true, completed:true });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error:"تعذر حفظ تقدم الدرس" });
  }
});

/* =========================================================
   DASHBOARD
========================================================= */

app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const u = await db(`
      SELECT id,name,email,wallet_balance,subscribed
      FROM users WHERE id=$1
    `, [req.user.id]);

    if (!u.rows[0]) return res.status(404).json({ error: "المستخدم غير موجود" });

    const p = await db(`
      SELECT l.id,l.title,c.title AS course_title,c.slug AS course_slug,
             l.sort_order AS lesson_sort_order,
             lp.completed,lp.score,lp.last_attempt_at,lp.updated_at
      FROM lessons l
      JOIN courses c ON c.id=l.course_id
      LEFT JOIN lesson_progress lp
        ON lp.lesson_id=l.id AND lp.user_id=$1
      WHERE c.is_published=true AND l.is_published=true
      ORDER BY c.sort_order,c.id,l.sort_order,l.id
    `, [req.user.id]);

    const lessons = p.rows;
    const completed = lessons.filter(x => x.completed);
    const scores = lessons.filter(x => x.score !== null).map(x => Number(x.score));
    const touched = lessons.filter(x => x.updated_at);
    touched.sort((a,b) => new Date(b.updated_at) - new Date(a.updated_at));
    const lastLesson = touched[0] || null;
    let resumeLesson = lastLesson;
    if (lastLesson?.completed) {
      const sameCourse = lessons
        .filter(x => x.course_slug === lastLesson.course_slug)
        .sort((a,b) => Number(a.lesson_sort_order||0)-Number(b.lesson_sort_order||0) || Number(a.id)-Number(b.id));
      const idx = sameCourse.findIndex(x => Number(x.id) === Number(lastLesson.id));
      resumeLesson = sameCourse[idx + 1] || lastLesson;
    }
    const average = scores.length ? Math.round(scores.reduce((a,b)=>a+b,0)/scores.length) : 0;
    const courses = {};
    for (const row of lessons) {
      const key = row.course_title;
      if (!courses[key]) courses[key] = { title:key, total:0, completed:0, percent:0 };
      courses[key].total++;
      if (row.completed) courses[key].completed++;
    }
    Object.values(courses).forEach(c => { c.percent = c.total ? Math.round(c.completed / c.total * 100) : 0; });

    res.json({
      user: publicUser(u.rows[0]),
      progress: {
        totalLessons: lessons.length,
        completedLessons: completed.length,
        percent: lessons.length ? Math.round(completed.length / lessons.length * 100) : 0,
        averageScore: average,
        lastLesson,
        resumeLesson,
        lessons,
        courses: Object.values(courses)
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر تحميل لوحة الطالب" });
  }
});

/* =========================================================
   SUBSCRIPTION
========================================================= */

app.post("/api/subscribe", auth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const s = await client.query("SELECT subscription_price,subscription_weeks FROM site_settings WHERE id=1");
    const price = Number(s.rows[0]?.subscription_price || 0);
    const weeks = Math.max(1, Number(s.rows[0]?.subscription_weeks || 25));

    const u = await client.query(`
      SELECT wallet_balance,subscribed,subscription_expires_at
      FROM users WHERE id=$1 FOR UPDATE
    `, [req.user.id]);

    if (!u.rows[0]) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "المستخدم غير موجود" });
    }

    if (subscriptionActive(u.rows[0])) {
      await client.query("COMMIT");
      return res.json({ subscribed: true, wallet_balance: Number(u.rows[0].wallet_balance), subscription_expires_at:u.rows[0].subscription_expires_at });
    }

    if (Number(u.rows[0].wallet_balance) < price) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: `الرصيد غير كافٍ. سعر الاشتراك ${price} جنيه` });
    }

    await client.query(`
      UPDATE users SET wallet_balance=wallet_balance-$1,subscribed=true,subscription_started_at=NOW(),subscription_expires_at=NOW()+($2 * INTERVAL '1 week')
      WHERE id=$3
    `, [price, weeks, req.user.id]);

    await client.query(`
      INSERT INTO wallet_transactions(user_id,amount,type,note)
      VALUES($1,$2,'subscription',$3)
    `, [req.user.id, -price, "اشتراك جميع الكورسات"]);

    await client.query("COMMIT");

    const updated = await db("SELECT wallet_balance,subscribed,subscription_started_at,subscription_expires_at FROM users WHERE id=$1", [req.user.id]);
    res.json({ subscribed: true, wallet_balance: Number(updated.rows[0].wallet_balance), subscription_started_at:updated.rows[0].subscription_started_at, subscription_expires_at:updated.rows[0].subscription_expires_at });
  } catch (e) {
    try { await client.query("ROLLBACK"); } catch {}
    console.error(e);
    res.status(500).json({ error: "تعذر تنفيذ الاشتراك" });
  } finally {
    client.release();
  }
});

/* =========================================================
   ADMIN: SETTINGS / USERS
========================================================= */

app.get("/api/admin/settings", auth, adminOnly, async (req,res) => {
  try {
    const r = await db("SELECT * FROM site_settings WHERE id=1");
    res.json(r.rows[0]);
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"تعذر تحميل الإعدادات"});
  }
});

app.put("/api/admin/settings", auth, adminOnly, async (req,res) => {
  try {
    const b = req.body;
    const r = await db(`
      UPDATE site_settings SET
        site_name=$1,tagline=$2,subscription_price=$3,subscription_weeks=$4,
        hero_title=$5,hero_text=$6,hero_image=$7,updated_at=NOW()
      WHERE id=1 RETURNING *
    `, [
      b.site_name ?? "StudyMedSmart",
      b.tagline ?? "منصة تعليمية طبية",
      Number(b.subscription_price) || 0,
      Math.max(1, Math.floor(Number(b.subscription_weeks) || 25)),
      b.hero_title ?? "ابدأ رحلتك الطبية بثقة",
      b.hero_text ?? "تعلم أساسيات المجال الطبي في مكان واحد.",
      String(b.hero_image ?? "")
    ]);
    res.json(r.rows[0]);
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"تعذر حفظ الإعدادات"});
  }
});

app.get("/api/social-links", async (req,res)=>{try{const r=await db("SELECT id,platform,url,sort_order FROM site_social_links WHERE is_active=true AND url<>'' ORDER BY sort_order,id");res.json(r.rows);}catch(e){res.status(500).json({error:"تعذر تحميل روابط التواصل"});}});
app.get("/api/admin/social-links", auth, adminOnly, async (req,res)=>{try{res.json((await db("SELECT * FROM site_social_links ORDER BY sort_order,id")).rows);}catch(e){res.status(500).json({error:"تعذر تحميل روابط التواصل"});}});
app.put("/api/admin/social-links", auth, adminOnly, async (req,res)=>{const links=Array.isArray(req.body.links)?req.body.links:[];const c=await pool.connect();try{await c.query("BEGIN");await c.query("DELETE FROM site_social_links");for(let i=0;i<links.length;i++){const x=links[i]||{};const platform=String(x.platform||"").trim();const url=String(x.url||"").trim();if(!platform||!url)continue;if(!/^https?:\/\//i.test(url))throw new Error("كل روابط التواصل يجب أن تبدأ بـ http:// أو https://");await c.query("INSERT INTO site_social_links(platform,url,sort_order,is_active,updated_at) VALUES($1,$2,$3,true,NOW())",[platform,url,i]);}await c.query("COMMIT");res.json((await db("SELECT * FROM site_social_links WHERE is_active=true AND url<>'' ORDER BY sort_order,id")).rows);}catch(e){try{await c.query("ROLLBACK")}catch{}res.status(400).json({error:e.message||"تعذر حفظ روابط التواصل"});}finally{c.release();}});
app.delete("/api/admin/social-links/:id", auth, adminOnly, async (req,res)=>{try{const r=await db("DELETE FROM site_social_links WHERE id=$1 RETURNING id",[req.params.id]);if(!r.rows[0])return res.status(404).json({error:"الرابط غير موجود"});res.json({ok:true});}catch(e){res.status(500).json({error:"تعذر حذف الرابط"});}});
app.post("/api/auth/logout", auth, async(req,res)=>{try{await invalidateSession(req.user.jti);res.json({ok:true});}catch{res.status(500).json({error:"تعذر تسجيل الخروج"});}});

app.get("/api/admin/users", auth, adminOnly, async (req,res) => {
  try {
    const r = await db(`
      SELECT id,name,email,role,wallet_balance,subscribed,subscription_started_at,subscription_expires_at,created_at
      FROM users ORDER BY id DESC
    `);
    res.json(r.rows.map(x => ({...x,wallet_balance:Number(x.wallet_balance||0)})));
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"تعذر تحميل الطلاب"});
  }
});

app.post("/api/admin/users/:id/credit", auth, adminOnly, async (req,res) => {
  const client = await pool.connect();
  try {
    const amount = Number(req.body.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({error:"قيمة الرصيد غير صحيحة"});
    }

    await client.query("BEGIN");
    const u = await client.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [req.params.id]);
    if (!u.rows[0]) {
      await client.query("ROLLBACK");
      return res.status(404).json({error:"الطالب غير موجود"});
    }

    await client.query("UPDATE users SET wallet_balance=wallet_balance+$1 WHERE id=$2", [amount,req.params.id]);
    await client.query(`
      INSERT INTO wallet_transactions(user_id,amount,type,note)
      VALUES($1,$2,'credit',$3)
    `,[req.params.id,amount,req.body.note || "إضافة رصيد من الإدارة"]);

    await client.query("COMMIT");
    res.json({ok:true});
  } catch(e) {
    try { await client.query("ROLLBACK"); } catch {}
    console.error(e);
    res.status(500).json({error:"تعذر إضافة الرصيد"});
  } finally {
    client.release();
  }
});

/* =========================================================
   ADMIN: COURSES / LESSONS
========================================================= */

app.delete("/api/admin/users/:id", auth, adminOnly, async (req,res)=>{
  try{
    const id=Number(req.params.id);
    const r=await db("DELETE FROM users WHERE id=$1 AND role<>\'admin\' RETURNING id",[id]);
    if(!r.rows[0]) return res.status(404).json({error:"الطالب غير موجود أو لا يمكن حذف حساب الإدارة."});
    res.json({ok:true});
  }catch(e){console.error(e);res.status(500).json({error:"تعذر حذف الطالب"});}
});
app.post("/api/admin/users/:id/unsubscribe", auth, adminOnly, async (req,res)=>{
  try{const r=await db("UPDATE users SET subscribed=false,subscription_started_at=NULL,subscription_expires_at=NULL WHERE id=$1 AND role<>\'admin\' RETURNING id",[req.params.id]);if(!r.rows[0])return res.status(404).json({error:"الطالب غير موجود"});res.json({ok:true});}
  catch(e){console.error(e);res.status(500).json({error:"تعذر إلغاء اشتراك الطالب"});}
});
app.post("/api/admin/users/unsubscribe-all", auth, adminOnly, async (req,res)=>{
  try{const r=await db("UPDATE users SET subscribed=false,subscription_started_at=NULL,subscription_expires_at=NULL WHERE role<>\'admin\' RETURNING id");res.json({ok:true,count:r.rowCount});}
  catch(e){console.error(e);res.status(500).json({error:"تعذر إلغاء جميع الاشتراكات"});}
});
app.delete("/api/admin/users", auth, adminOnly, async (req,res)=>{
  try{const r=await db("DELETE FROM users WHERE role<>\'admin\' RETURNING id");res.json({ok:true,count:r.rowCount});}
  catch(e){console.error(e);res.status(500).json({error:"تعذر حذف جميع الطلاب"});}
});

app.get("/api/admin/courses", auth, adminOnly, async (req,res) => {
  try {
    const r = await db("SELECT * FROM courses ORDER BY sort_order,id");
    res.json(r.rows);
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"تعذر تحميل الكورسات"});
  }
});

app.post("/api/admin/courses", auth, adminOnly, async (req,res) => {
  try {
    const b=req.body;
    if(!b.title || !b.slug) return res.status(400).json({error:"اسم الكورس والـ slug مطلوبان"});
    const r=await db(`
      INSERT INTO courses(title,slug,description,image_url,sort_order,is_published)
      VALUES($1,$2,$3,$4,$5,$6) RETURNING *
    `,[b.title,b.slug,b.description||"",b.image_url||"",Number(b.sort_order)||0,b.is_published!==false]);
    res.status(201).json(r.rows[0]);
  }catch(e){
    if(e.code==="23505") return res.status(409).json({error:"هذا الـ slug مستخدم بالفعل"});
    console.error(e); res.status(500).json({error:"تعذر إنشاء الكورس"});
  }
});

app.put("/api/admin/courses/:id", auth, adminOnly, async (req,res) => {
  try {
    const b=req.body;
    const r=await db(`
      UPDATE courses SET
        title=$1,slug=$2,description=$3,image_url=$4,
        sort_order=$5,is_published=$6
      WHERE id=$7 RETURNING *
    `,[b.title,b.slug,b.description||"",b.image_url||"",Number(b.sort_order)||0,b.is_published!==false,req.params.id]);
    if(!r.rows[0]) return res.status(404).json({error:"الكورس غير موجود"});
    res.json(r.rows[0]);
  }catch(e){
    if(e.code==="23505") return res.status(409).json({error:"هذا الـ slug مستخدم بالفعل"});
    console.error(e); res.status(500).json({error:"تعذر تعديل الكورس"});
  }
});

app.delete("/api/admin/courses/:id", auth, adminOnly, async (req,res) => {
  try {
    const r=await db("DELETE FROM courses WHERE id=$1 RETURNING id",[req.params.id]);
    if(!r.rows[0]) return res.status(404).json({error:"الكورس غير موجود"});
    res.json({ok:true});
  }catch(e){ console.error(e); res.status(500).json({error:"تعذر حذف الكورس"}); }
});

app.get("/api/admin/courses/:id/lessons", auth, adminOnly, async (req,res) => {
  try {
    const r=await db(`
      SELECT l.*,q.id AS quiz_id,q.passing_score
      FROM lessons l LEFT JOIN quizzes q ON q.lesson_id=l.id
      WHERE l.course_id=$1 ORDER BY l.sort_order,l.id
    `,[req.params.id]);
    res.json(r.rows);
  }catch(e){console.error(e);res.status(500).json({error:"تعذر تحميل الدروس"});}
});

app.post("/api/admin/lessons", auth, adminOnly, async (req,res) => {
  try {
    const b=req.body;
    if(!b.course_id || !b.title) return res.status(400).json({error:"الكورس واسم الدرس مطلوبان"});
    const r=await db(`
      INSERT INTO lessons(course_id,title,description,video_url,pdf_url,sort_order,is_published)
      VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *
    `,[b.course_id,b.title,b.description||"",b.video_url||"",b.pdf_url||"",Number(b.sort_order)||0,b.is_published!==false]);
    res.status(201).json(r.rows[0]);
  }catch(e){console.error(e);res.status(500).json({error:"تعذر إنشاء الدرس"});}
});

app.put("/api/admin/lessons/:id", auth, adminOnly, async (req,res) => {
  try {
    const b=req.body;
    const r=await db(`
      UPDATE lessons SET
        title=$1,description=$2,video_url=$3,pdf_url=$4,
        sort_order=$5,is_published=$6
      WHERE id=$7 RETURNING *
    `,[b.title,b.description||"",b.video_url||"",b.pdf_url||"",Number(b.sort_order)||0,b.is_published!==false,req.params.id]);
    if(!r.rows[0]) return res.status(404).json({error:"الدرس غير موجود"});
    res.json(r.rows[0]);
  }catch(e){console.error(e);res.status(500).json({error:"تعذر تعديل الدرس"});}
});

app.delete("/api/admin/lessons/:id", auth, adminOnly, async (req,res) => {
  try {
    const r=await db("DELETE FROM lessons WHERE id=$1 RETURNING id",[req.params.id]);
    if(!r.rows[0]) return res.status(404).json({error:"الدرس غير موجود"});
    res.json({ok:true});
  }catch(e){console.error(e);res.status(500).json({error:"تعذر حذف الدرس"});}
});

app.get("/api/admin/lessons/:id/quiz", auth, adminOnly, async (req,res) => {
  try {
    const qr=await db("SELECT * FROM quizzes WHERE lesson_id=$1",[req.params.id]);
    if(!qr.rows[0]) return res.json(null);
    const qs=await db(`
      SELECT id,question,option_a,option_b,option_c,option_d,correct_option,explanation,sort_order
      FROM quiz_questions WHERE quiz_id=$1 ORDER BY sort_order,id
    `,[qr.rows[0].id]);
    res.json({...qr.rows[0],questions:qs.rows});
  }catch(e){console.error(e);res.status(500).json({error:"تعذر تحميل الاختبار"});}
});

app.post("/api/admin/quizzes", auth, adminOnly, async (req,res) => {
  const client=await pool.connect();
  try{
    const b=req.body;
    const lessonId=Number(b.lesson_id);
    const pass=Number(b.passing_score);
    const questions=Array.isArray(b.questions)?b.questions:[];
    if(!lessonId) return res.status(400).json({error:"lesson_id مطلوب"});
    if(!Number.isFinite(pass)||pass<0||pass>100) return res.status(400).json({error:"نسبة النجاح يجب أن تكون بين 0 و100"});

    await client.query("BEGIN");
    const q=await client.query(`
      INSERT INTO quizzes(lesson_id,passing_score)
      VALUES($1,$2)
      ON CONFLICT(lesson_id) DO UPDATE SET passing_score=EXCLUDED.passing_score
      RETURNING id
    `,[lessonId,pass]);

    await client.query("DELETE FROM quiz_questions WHERE quiz_id=$1",[q.rows[0].id]);

    for(let i=0;i<questions.length;i++){
      const x=questions[i];
      const correct=String(x.correct_option||"").toUpperCase();
      if(!["A","B","C","D"].includes(correct)) throw new Error(`الإجابة الصحيحة غير صالحة في السؤال ${i+1}`);
      await client.query(`
        INSERT INTO quiz_questions
        (quiz_id,question,option_a,option_b,option_c,option_d,correct_option,explanation,sort_order)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
      `,[q.rows[0].id,x.question||"",x.option_a||"",x.option_b||"",x.option_c||"",x.option_d||"",correct,x.explanation||"",i]);
    }

    await client.query("COMMIT");
    res.json({ok:true,quiz_id:q.rows[0].id});
  }catch(e){
    try{await client.query("ROLLBACK")}catch{}
    console.error(e); res.status(500).json({error:e.message||"تعذر حفظ الاختبار"});
  }finally{client.release();}
});

app.delete("/api/admin/lessons/:id/quiz", auth, adminOnly, async (req,res) => {
  try{
    await db("DELETE FROM quizzes WHERE lesson_id=$1",[req.params.id]);
    res.json({ok:true});
  }catch(e){console.error(e);res.status(500).json({error:"تعذر حذف الاختبار"});}
});

/* =========================================================
   API 404
========================================================= */

app.use("/api", (req,res) => {
  res.status(404).json({error:"API endpoint not found"});
});

/* =========================================================
   FRONTEND
   Exactly two HTML files in the repository.
========================================================= */

app.get("/", (req,res) => res.sendFile(path.resolve("index.html")));
app.get("/index.html", (req,res) => res.sendFile(path.resolve("index.html")));
app.get("/admin", (req,res) => res.sendFile(path.resolve("admin.html")));
app.get("/admin.html", (req,res) => res.sendFile(path.resolve("admin.html")));

app.use((req,res) => {
  res.status(404).send("Page not found");
});

/* =========================================================
   START
========================================================= */

async function start() {
  try {
    await initDatabase();
    await db("SELECT 1");
    app.listen(PORT,"0.0.0.0",()=>console.log(`StudyMedSmart running on port ${PORT}`));
  } catch(e) {
    console.error("SERVER STARTUP FAILED:",e);
    process.exit(1);
  }
}

start();
