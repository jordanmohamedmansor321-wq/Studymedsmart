import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs';

const { Pool } = pg;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

async function db(sql, params = []) {
  return pool.query(sql, params);
}

function token(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'تسجيل الدخول مطلوب'
      });
    }

    const accessToken = header.slice(7);

    req.user = jwt.verify(accessToken, JWT_SECRET);

    next();
  } catch {
    return res.status(401).json({
      error: 'جلسة الدخول غير صالحة'
    });
  }
}

function admin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({
      error: 'غير مصرح'
    });
  }

  next();
}

/* =========================================================
   HEALTH
========================================================= */

app.get('/healthz', (req, res) => {
  res.json({
    ok: true,
    service: 'StudyMedSmart'
  });
});

/* =========================================================
   SETTINGS
========================================================= */

app.get('/api/settings', async (req, res) => {
  try {
    const result = await db(
      'SELECT * FROM site_settings WHERE id = 1'
    );

    res.json(result.rows[0] || null);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================================================
   COURSES
========================================================= */

app.get('/api/courses', async (req, res) => {
  try {
    const result = await db(`
      SELECT *
      FROM courses
      WHERE is_published = true
      ORDER BY sort_order, id
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: error.message
    });
  }
});

app.get('/api/courses/:slug', async (req, res) => {
  try {
    const courseResult = await db(
      `
      SELECT *
      FROM courses
      WHERE slug = $1
      AND is_published = true
      `,
      [req.params.slug]
    );

    if (!courseResult.rows[0]) {
      return res.status(404).json({
        error: 'الكورس غير موجود'
      });
    }

    const course = courseResult.rows[0];

    const lessonsResult = await db(
      `
      SELECT
        l.*,
        q.id AS quiz_id,
        q.passing_score
      FROM lessons l
      LEFT JOIN quizzes q
        ON q.lesson_id = l.id
      WHERE l.course_id = $1
      AND l.is_published = true
      ORDER BY l.sort_order, l.id
      `,
      [course.id]
    );

    res.json({
      ...course,
      lessons: lessonsResult.rows
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================================================
   AUTH - REGISTER
========================================================= */

app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      name,
      email,
      password
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: 'أدخل الاسم والبريد وكلمة المرور'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const hash = await bcrypt.hash(password, 10);

    const result = await db(
      `
      INSERT INTO users
      (
        name,
        email,
        password_hash
      )
      VALUES
      ($1, $2, $3)
      RETURNING
        id,
        name,
        email,
        role,
        wallet_balance,
        subscribed
      `,
      [
        name.trim(),
        normalizedEmail,
        hash
      ]
    );

    const user = result.rows[0];

    res.json({
      user,
      token: token(user)
    });
  } catch (error) {
    console.error(error);

    res.status(
      error.code === '23505' ? 409 : 500
    ).json({
      error:
        error.code === '23505'
          ? 'البريد مستخدم بالفعل'
          : error.message
    });
  }
});

/* =========================================================
   AUTH - LOGIN
========================================================= */

app.post('/api/auth/login', async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'أدخل البريد وكلمة المرور'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const result = await db(
      `
      SELECT *
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
    );

    const user = result.rows[0];

    if (
      !user ||
      !(await bcrypt.compare(
        password,
        user.password_hash
      ))
    ) {
      return res.status(401).json({
        error: 'البريد أو كلمة المرور غير صحيحة'
      });
    }

    res.json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        wallet_balance: user.wallet_balance,
        subscribed: user.subscribed
      },
      token: token(user)
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get('/api/me', auth, async (req, res) => {
  try {
    const result = await db(
      `
      SELECT
        id,
        name,
        email,
        role,
        wallet_balance,
        subscribed
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: 'المستخدم غير موجود'
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================================================
   LESSON
========================================================= */

app.get(
  '/api/courses/:slug/lessons/:lessonId',
  auth,
  async (req, res) => {
    try {
      const result = await db(
        `
        SELECT
          l.*,
          q.id AS quiz_id,
          q.passing_score
        FROM lessons l
        LEFT JOIN quizzes q
          ON q.lesson_id = l.id
        JOIN courses c
          ON c.id = l.course_id
        WHERE c.slug = $1
        AND l.id = $2
        AND l.is_published = true
        `,
        [
          req.params.slug,
          req.params.lessonId
        ]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: 'الدرس غير موجود'
        });
      }

      res.json(result.rows[0]);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   QUIZ
========================================================= */

app.get(
  '/api/lessons/:lessonId/quiz',
  auth,
  async (req, res) => {
    try {
      const quizResult = await db(
        `
        SELECT *
        FROM quizzes
        WHERE lesson_id = $1
        `,
        [req.params.lessonId]
      );

      if (!quizResult.rows[0]) {
        return res.status(404).json({
          error: 'لا يوجد اختبار'
        });
      }

      const quiz = quizResult.rows[0];

      const questionsResult = await db(
        `
        SELECT
          id,
          question,
          option_a,
          option_b,
          option_c,
          option_d,
          sort_order
        FROM quiz_questions
        WHERE quiz_id = $1
        ORDER BY sort_order, id
        `,
        [quiz.id]
      );

      res.json({
        ...quiz,
        questions: questionsResult.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   SUBMIT QUIZ
========================================================= */

app.post(
  '/api/lessons/:lessonId/quiz/submit',
  auth,
  async (req, res) => {
    try {
      const {
        answers = {}
      } = req.body;

      const quizResult = await db(
        `
        SELECT *
        FROM quizzes
        WHERE lesson_id = $1
        `,
        [req.params.lessonId]
      );

      if (!quizResult.rows[0]) {
        return res.status(404).json({
          error: 'لا يوجد اختبار'
        });
      }

      const quiz = quizResult.rows[0];

      const questionsResult = await db(
        `
        SELECT *
        FROM quiz_questions
        WHERE quiz_id = $1
        ORDER BY sort_order, id
        `,
        [quiz.id]
      );

      const questions = questionsResult.rows;

      let correct = 0;

      const results = questions.map(question => {
        const selected = String(
          answers[question.id] || ''
        ).toUpperCase();

        const correctOption = String(
          question.correct_option
        ).toUpperCase();

        const isCorrect =
          selected === correctOption;

        if (isCorrect) {
          correct++;
        }

        return {
          id: question.id,
          selected,
          correct_option: correctOption,
          explanation: question.explanation,
          correct: isCorrect
        };
      });

      const total = questions.length;

      const score = total
        ? Math.round((correct / total) * 100)
        : 0;

      const passed =
        score >= Number(quiz.passing_score);

      await db(
        `
        INSERT INTO lesson_progress
        (
          user_id,
          lesson_id,
          completed,
          score,
          attempts,
          last_attempt_at
        )
        VALUES
        ($1, $2, $3, $4, 1, NOW())
        ON CONFLICT
        (
          user_id,
          lesson_id
        )
        DO UPDATE SET
          completed = EXCLUDED.completed,
          score = EXCLUDED.score,
          attempts = lesson_progress.attempts + 1,
          last_attempt_at = NOW()
        `,
        [
          req.user.id,
          req.params.lessonId,
          passed,
          score
        ]
      );

      res.json({
        score,
        passed,
        passing_score: quiz.passing_score,
        total,
        correct,
        results
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   DASHBOARD
========================================================= */

app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const userResult = await db(
      `
      SELECT
        id,
        name,
        email,
        wallet_balance,
        subscribed
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    const user = userResult.rows[0];

    if (!user) {
      return res.status(404).json({
        error: 'المستخدم غير موجود'
      });
    }

    const progressResult = await db(
      `
      SELECT
        l.id,
        l.title,
        c.title AS course_title,
        lp.completed,
        lp.score,
        lp.last_attempt_at
      FROM lessons l
      JOIN courses c
        ON c.id = l.course_id
      LEFT JOIN lesson_progress lp
        ON lp.lesson_id = l.id
        AND lp.user_id = $1
      WHERE c.is_published = true
      AND l.is_published = true
      ORDER BY
        c.sort_order,
        l.sort_order,
        l.id
      `,
      [req.user.id]
    );

    const lessons = progressResult.rows;

    const completedLessons =
      lessons.filter(
        lesson => lesson.completed
      );

    const scores = lessons
      .filter(
        lesson => lesson.score !== null
      )
      .map(
        lesson => Number(lesson.score)
      );

    const completedCount =
      completedLessons.length;

    const totalLessons =
      lessons.length;

    const percent =
      totalLessons > 0
        ? Math.round(
            (completedCount / totalLessons) *
              100
          )
        : 0;

    const averageScore =
      scores.length > 0
        ? Math.round(
            scores.reduce(
              (sum, score) => sum + score,
              0
            ) / scores.length
          )
        : 0;

    const lastLesson =
      completedLessons.length
        ? completedLessons[
            completedLessons.length - 1
          ]
        : null;

    res.json({
      user,
      progress: {
        totalLessons,
        completedLessons: completedCount,
        percent,
        averageScore,
        lastLesson,
        lessons
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: error.message
    });
  }
});

/* =========================================================
   SUBSCRIBE
========================================================= */

app.post('/api/subscribe', auth, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const settingsResult =
      await client.query(
        `
        SELECT subscription_price
        FROM site_settings
        WHERE id = 1
        `
      );

    if (!settingsResult.rows[0]) {
      await client.query('ROLLBACK');

      return res.status(500).json({
        error: 'إعدادات الاشتراك غير موجودة'
      });
    }

    const price = Number(
      settingsResult.rows[0]
        .subscription_price
    );

    const userResult =
      await client.query(
        `
        SELECT
          wallet_balance,
          subscribed
        FROM users
        WHERE id = $1
        FOR UPDATE
        `,
        [req.user.id]
      );

    const user = userResult.rows[0];

    if (!user) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'المستخدم غير موجود'
      });
    }

    if (user.subscribed) {
      await client.query('COMMIT');

      return res.json({
        subscribed: true
      });
    }

    if (Number(user.wallet_balance) < price) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: `الرصيد غير كافٍ. سعر الاشتراك ${price}`
      });
    }

    await client.query(
      `
      UPDATE users
      SET
        wallet_balance =
          wallet_balance - $1,
        subscribed = true
      WHERE id = $2
      `,
      [
        price,
        req.user.id
      ]
    );

    await client.query(
      `
      INSERT INTO wallet_transactions
      (
        user_id,
        amount,
        type,
        note
      )
      VALUES
      ($1, $2, 'subscription', $3)
      `,
      [
        req.user.id,
        -price,
        'اشتراك جميع الكورسات'
      ]
    );

    await client.query('COMMIT');

    res.json({
      subscribed: true
    });
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {}

    console.error(error);

    res.status(500).json({
      error: error.message
    });
  } finally {
    client.release();
  }
});

/* =========================================================
   ADMIN - USERS
========================================================= */

app.get(
  '/api/admin/users',
  auth,
  admin,
  async (req, res) => {
    try {
      const result = await db(`
        SELECT
          id,
          name,
          email,
          role,
          wallet_balance,
          subscribed,
          created_at
        FROM users
        ORDER BY id DESC
      `);

      res.json(result.rows);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   ADMIN - CREDIT WALLET
========================================================= */

app.post(
  '/api/admin/users/:id/credit',
  auth,
  admin,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const amount = Number(
        req.body.amount
      );

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          error: 'قيمة غير صحيحة'
        });
      }

      await client.query('BEGIN');

      await client.query(
        `
        UPDATE users
        SET wallet_balance =
          wallet_balance + $1
        WHERE id = $2
        `,
        [
          amount,
          req.params.id
        ]
      );

      await client.query(
        `
        INSERT INTO wallet_transactions
        (
          user_id,
          amount,
          type,
          note
        )
        VALUES
        ($1, $2, 'credit', $3)
        `,
        [
          req.params.id,
          amount,
          req.body.note ||
            'إضافة رصيد من الإدارة'
        ]
      );

      await client.query('COMMIT');

      res.json({
        ok: true
      });
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {}

      console.error(error);

      res.status(500).json({
        error: error.message
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   ADMIN - SETTINGS
========================================================= */

app.put(
  '/api/admin/settings',
  auth,
  admin,
  async (req, res) => {
    try {
      const {
        site_name,
        tagline,
        subscription_price,
        hero_title,
        hero_text
      } = req.body;

      const result = await db(
        `
        UPDATE site_settings
        SET
          site_name = $1,
          tagline = $2,
          subscription_price = $3,
          hero_title = $4,
          hero_text = $5
        WHERE id = 1
        RETURNING *
        `,
        [
          site_name,
          tagline,
          subscription_price,
          hero_title,
          hero_text
        ]
      );

      res.json(result.rows[0]);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   ADMIN - COURSES
========================================================= */

app.post(
  '/api/admin/courses',
  auth,
  admin,
  async (req, res) => {
    try {
      const {
        title,
        slug,
        description,
        image_url,
        sort_order = 0
      } = req.body;

      if (!title || !slug) {
        return res.status(400).json({
          error: 'اسم الكورس وSlug مطلوبان'
        });
      }

      const result = await db(
        `
        INSERT INTO courses
        (
          title,
          slug,
          description,
          image_url,
          sort_order
        )
        VALUES
        ($1, $2, $3, $4, $5)
        RETURNING *
        `,
        [
          title,
          slug,
          description || '',
          image_url || '',
          sort_order
        ]
      );

      res.json(result.rows[0]);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   ADMIN - LESSONS
========================================================= */

app.post(
  '/api/admin/lessons',
  auth,
  admin,
  async (req, res) => {
    try {
      const {
        course_id,
        title,
        description,
        video_url,
        pdf_url,
        sort_order = 0
      } = req.body;

      if (!course_id || !title) {
        return res.status(400).json({
          error: 'الكورس واسم الدرس مطلوبان'
        });
      }

      const result = await db(
        `
        INSERT INTO lessons
        (
          course_id,
          title,
          description,
          video_url,
          pdf_url,
          sort_order
        )
        VALUES
        ($1, $2, $3, $4, $5, $6)
        RETURNING *
        `,
        [
          course_id,
          title,
          description || '',
          video_url || '',
          pdf_url || '',
          sort_order
        ]
      );

      res.json(result.rows[0]);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: error.message
      });
    }
  }
);

/* =========================================================
   ADMIN - QUIZZES
========================================================= */

app.post(
  '/api/admin/quizzes',
  auth,
  admin,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const {
        lesson_id,
        passing_score = 50,
        questions = []
      } = req.body;

      if (!lesson_id) {
        return res.status(400).json({
          error: 'lesson_id مطلوب'
        });
      }

      await client.query('BEGIN');

      const quizResult =
        await client.query(
          `
          INSERT INTO quizzes
          (
            lesson_id,
            passing_score
          )
          VALUES
          ($1, $2)
          ON CONFLICT(lesson_id)
          DO UPDATE SET
            passing_score =
              EXCLUDED.passing_score
          RETURNING id
          `,
          [
            lesson_id,
            passing_score
          ]
        );

      const quizId =
        quizResult.rows[0].id;

      await client.query(
        `
        DELETE FROM quiz_questions
        WHERE quiz_id = $1
        `,
        [quizId]
      );

      for (
        let i = 0;
        i < questions.length;
        i++
      ) {
        const question =
          questions[i];

        await client.query(
          `
          INSERT INTO quiz_questions
          (
            quiz_id,
            question,
            option_a,
            option_b,
            option_c,
            option_d,
            correct_option,
            explanation,
            sort_order
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9
          )
          `,
          [
            quizId,
            question.question,
            question.option_a,
            question.option_b,
            question.option_c,
            question.option_d,
            question.correct_option,
            question.explanation || '',
            i
          ]
        );
      }

      await client.query('COMMIT');

      res.json({
        ok: true,
        quiz_id: quizId
      });
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {}

      console.error(error);

      res.status(500).json({
        error: error.message
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initDatabase() {
  if (!process.env.DATABASE_URL) {
    console.warn(
      'WARNING: DATABASE_URL is missing'
    );

    return;
  }

  try {
    const schemaPath = path.join(
      __dirname,
      'db',
      'schema.sql'
    );

    if (fs.existsSync(schemaPath)) {
      const schema = fs.readFileSync(
        schemaPath,
        'utf8'
      );

      const statements = schema
        .split(';')
        .map(statement => statement.trim())
        .filter(Boolean);

      for (const statement of statements) {
        await db(statement);
      }
    } else {
      console.warn(
        'db/schema.sql was not found'
      );
    }

    const adminEmail =
      process.env.ADMIN_EMAIL;

    const adminPassword =
      process.env.ADMIN_PASSWORD;

    if (
      adminEmail &&
      adminPassword
    ) {
      const hash =
        await bcrypt.hash(
          adminPassword,
          10
        );

      await db(
        `
        INSERT INTO users
        (
          name,
          email,
          password_hash,
          role
        )
        VALUES
        (
          'Administrator',
          $1,
          $2,
          'admin'
        )
        ON CONFLICT(email)
        DO UPDATE SET
          role = 'admin'
        `,
        [
          adminEmail
            .trim()
            .toLowerCase(),
          hash
        ]
      );
    }

    console.log(
      'Database initialization completed'
    );
  } catch (error) {
    console.error(
      'DB initialization failed:',
      error
    );
  }
}

/* =========================================================
   FRONTEND FALLBACK
   IMPORTANT:
   Express 5 does not accept app.get('*')
========================================================= */

app.get('/{*splat}', (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      'public',
      'index.html'
    )
  );
});

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await initDatabase();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(
        `StudyMedSmart listening on port ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      'Failed to start server:',
      error
    );

    process.exit(1);
  }
}

startServer();
