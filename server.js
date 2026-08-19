import express from "express";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "node:path";

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

function tokenFor(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Bearer ")) {
      return res.status(401).json({ error: "تسجيل الدخول مطلوب" });
    }
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "جلسة الدخول غير صالحة" });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({ error: "غير مصرح" });
  }
  next();
}

function publicUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    wallet_balance: Number(row.wallet_balance || 0),
    subscribed: !!row.subscribed
  };
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
      hero_title TEXT NOT NULL DEFAULT 'ابدأ رحلتك الطبية بثقة',
      hero_text TEXT NOT NULL DEFAULT 'تعلم أساسيات المجال الطبي في مكان واحد.',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      wallet_balance NUMERIC(12,2) NOT NULL DEFAULT 0,
      subscribed BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

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
    res.status(201).json({ user: publicUser(user), token: tokenFor(user) });
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

    res.json({ user: publicUser(user), token: tokenFor(user) });
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

    const user = await db("SELECT subscribed FROM users WHERE id=$1", [req.user.id]);
    const subscribed = !!user.rows[0]?.subscribed;
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

app.get("/api/lessons/:lessonId/quiz", auth, async (req, res) => {
  try {
    const user = await db("SELECT subscribed FROM users WHERE id=$1", [req.user.id]);
    if (!user.rows[0]?.subscribed) {
      return res.status(402).json({ locked: true, subscribed: false, message: "يجب عليك الاشتراك في StudyMedSmart للوصول إلى الاختبار." });
    }
    const qr = await db("SELECT * FROM quizzes WHERE lesson_id=$1", [req.params.lessonId]);
    if (!qr.rows[0]) return res.status(404).json({ error: "لا يوجد اختبار لهذا الدرس" });

    const q = await db(`
      SELECT id,question,option_a,option_b,option_c,option_d,sort_order
      FROM quiz_questions
      WHERE quiz_id=$1
      ORDER BY sort_order,id
    `, [qr.rows[0].id]);

    res.json({ ...qr.rows[0], questions: q.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر تحميل الاختبار" });
  }
});

app.post("/api/lessons/:lessonId/quiz/submit", auth, async (req, res) => {
  try {
    const answers = req.body.answers || {};
    const user = await db("SELECT subscribed FROM users WHERE id=$1", [req.user.id]);
    if (!user.rows[0]?.subscribed) {
      return res.status(402).json({ locked: true, subscribed: false, message: "يجب عليك الاشتراك في StudyMedSmart للوصول إلى الاختبار." });
    }
    const qr = await db("SELECT * FROM quizzes WHERE lesson_id=$1", [req.params.lessonId]);
    if (!qr.rows[0]) return res.status(404).json({ error: "لا يوجد اختبار لهذا الدرس" });

    const questions = (await db(`
      SELECT * FROM quiz_questions
      WHERE quiz_id=$1 ORDER BY sort_order,id
    `, [qr.rows[0].id])).rows;

    let correct = 0;
    const results = questions.map(q => {
      const selected = String(answers[q.id] || "").toUpperCase();
      const correctOption = String(q.correct_option || "").toUpperCase();
      const ok = selected === correctOption;
      if (ok) correct++;
      return {
        id: q.id,
        selected,
        correct_option: correctOption,
        explanation: q.explanation,
        correct: ok
      };
    });

    const total = questions.length;
    const score = total ? Math.round(correct / total * 100) : 0;
    const passingScore = Number(qr.rows[0].passing_score);
    const passed = score >= passingScore;

    await db(`
      INSERT INTO lesson_progress
        (user_id,lesson_id,completed,score,attempts,last_attempt_at)
      VALUES ($1,$2,$3,$4,1,NOW())
      ON CONFLICT(user_id,lesson_id)
      DO UPDATE SET
        completed=EXCLUDED.completed,
        score=EXCLUDED.score,
        attempts=lesson_progress.attempts+1,
        last_attempt_at=NOW()
    `, [req.user.id, req.params.lessonId, passed, score]);

    res.json({ score, passed, passing_score: passingScore, total, correct, results });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "تعذر تصحيح الاختبار" });
  }
});

/* =========================================================
   LESSON COMPLETION
========================================================= */

app.post("/api/lessons/:lessonId/complete", auth, async (req, res) => {
  try {
    const lessonId = Number(req.params.lessonId);
    if (!Number.isInteger(lessonId) || lessonId <= 0) return res.status(400).json({ error: "معرف الدرس غير صحيح" });
    const u = await db("SELECT subscribed FROM users WHERE id=$1", [req.user.id]);
    if (!u.rows[0]) return res.status(404).json({ error: "المستخدم غير موجود" });
    if (!u.rows[0].subscribed) return res.status(402).json({ locked:true, subscribed:false, message:"يجب عليك الاشتراك في StudyMedSmart للوصول إلى محتوى هذا الكورس." });
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
      SELECT l.id,l.title,c.title AS course_title,
             lp.completed,lp.score,lp.last_attempt_at
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
        lastLesson: completed.length ? completed[completed.length - 1] : null,
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

    const s = await client.query("SELECT subscription_price FROM site_settings WHERE id=1");
    const price = Number(s.rows[0]?.subscription_price || 0);

    const u = await client.query(`
      SELECT wallet_balance,subscribed
      FROM users WHERE id=$1 FOR UPDATE
    `, [req.user.id]);

    if (!u.rows[0]) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "المستخدم غير موجود" });
    }

    if (u.rows[0].subscribed) {
      await client.query("COMMIT");
      return res.json({ subscribed: true, wallet_balance: Number(u.rows[0].wallet_balance) });
    }

    if (Number(u.rows[0].wallet_balance) < price) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: `الرصيد غير كافٍ. سعر الاشتراك ${price} جنيه` });
    }

    await client.query(`
      UPDATE users SET wallet_balance=wallet_balance-$1,subscribed=true
      WHERE id=$2
    `, [price, req.user.id]);

    await client.query(`
      INSERT INTO wallet_transactions(user_id,amount,type,note)
      VALUES($1,$2,'subscription',$3)
    `, [req.user.id, -price, "اشتراك جميع الكورسات"]);

    await client.query("COMMIT");

    const updated = await db("SELECT wallet_balance,subscribed FROM users WHERE id=$1", [req.user.id]);
    res.json({ subscribed: true, wallet_balance: Number(updated.rows[0].wallet_balance) });
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
        site_name=$1,tagline=$2,subscription_price=$3,
        hero_title=$4,hero_text=$5,updated_at=NOW()
      WHERE id=1 RETURNING *
    `, [
      b.site_name ?? "StudyMedSmart",
      b.tagline ?? "منصة تعليمية طبية",
      Number(b.subscription_price) || 0,
      b.hero_title ?? "ابدأ رحلتك الطبية بثقة",
      b.hero_text ?? "تعلم أساسيات المجال الطبي في مكان واحد."
    ]);
    res.json(r.rows[0]);
  } catch(e) {
    console.error(e);
    res.status(500).json({error:"تعذر حفظ الإعدادات"});
  }
});

app.get("/api/admin/users", auth, adminOnly, async (req,res) => {
  try {
    const r = await db(`
      SELECT id,name,email,role,wallet_balance,subscribed,created_at
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
