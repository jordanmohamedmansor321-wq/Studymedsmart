import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs';

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT = Number(process.env.PORT) || 10000;

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is missing.');
  process.exit(1);
}

if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is missing.');
  process.exit(1);
}

/* =========================
   DATABASE
========================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,

  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false,

  max: 5,

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000
});

pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL error:', err);
});

/* =========================
   MIDDLEWARE
========================= */

app.use(
  express.json({
    limit: '2mb'
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '2mb'
  })
);

/*
 * ملفات الموقع موجودة في جذر المشروع
 * وليس داخل public
 */
app.use(
  express.static(__dirname)
);

/* =========================
   DATABASE HELPER
========================= */

async function db(sql, params = []) {
  return pool.query(sql, params);
}

/* =========================
   JWT
========================= */

function createToken(user) {
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

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
  try {
    const header =
      req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'تسجيل الدخول مطلوب'
      });
    }

    const token =
      header.substring(7);

    req.user =
      jwt.verify(
        token,
        JWT_SECRET
      );

    next();

  } catch {
    return res.status(401).json({
      error: 'جلسة الدخول غير صالحة'
    });
  }
}

/* =========================
   ADMIN MIDDLEWARE
========================= */

function admin(req, res, next) {
  if (
    !req.user ||
    req.user.role !== 'admin'
  ) {
    return res.status(403).json({
      error: 'غير مصرح'
    });
  }

  next();
}

/* =========================
   HEALTH
========================= */

app.get(
  '/healthz',
  async (req, res) => {
    try {
      await db('SELECT 1');

      res.json({
        ok: true,
        database: true
      });

    } catch (error) {
      res.status(503).json({
        ok: false,
        database: false,
        error: error.message
      });
    }
  }
);

/* =========================
   SETTINGS
========================= */

app.get(
  '/api/settings',
  async (req, res) => {
    try {
      const result = await db(
        `SELECT *
         FROM site_settings
         WHERE id = 1`
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: 'إعدادات الموقع غير موجودة'
        });
      }

      res.json(result.rows[0]);

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: 'تعذر تحميل إعدادات الموقع'
      });
    }
  }
);

/* =========================
   COURSES
========================= */

app.get(
  '/api/courses',
  async (req, res) => {
    try {
      const result = await db(
        `SELECT *
         FROM courses
         WHERE is_published = true
         ORDER BY sort_order ASC, id ASC`
      );

      res.json(result.rows);

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: 'تعذر تحميل الكورسات'
      });
    }
  }
);

/* =========================
   COURSE DETAILS
========================= */

app.get(
  '/api/courses/:slug',
  async (req, res) => {
    try {
      const courseResult =
        await db(
          `SELECT *
           FROM courses
           WHERE slug = $1
           AND is_published = true`,
          [req.params.slug]
        );

      if (!courseResult.rows[0]) {
        return res.status(404).json({
          error: 'الكورس غير موجود'
        });
      }

      const course =
        courseResult.rows[0];

      const lessonsResult =
        await db(
          `SELECT
             l.id,
             l.course_id,
             l.title,
             l.description,
             l.video_url,
             l.pdf_url,
             l.sort_order,
             l.is_published,
             q.id AS quiz_id,
             q.passing_score
           FROM lessons l

           LEFT JOIN quizzes q
             ON q.lesson_id = l.id

           WHERE l.course_id = $1
           AND l.is_published = true

           ORDER BY
             l.sort_order ASC,
             l.id ASC`,
          [course.id]
        );

      res.json({
        ...course,
        lessons:
          lessonsResult.rows
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: 'تعذر تحميل الكورس'
      });
    }
  }
);

/* =========================
   REGISTER
========================= */

app.post(
  '/api/auth/register',
  async (req, res) => {
    try {
      const {
        name,
        email,
        password
      } = req.body;

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          error: 'جميع البيانات مطلوبة'
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            'كلمة المرور يجب أن تكون 6 أحرف على الأقل'
        });
      }

      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();

      const hash =
        await bcrypt.hash(
          password,
          10
        );

      const result =
        await db(
          `INSERT INTO users
           (
             name,
             email,
             password_hash
           )
           VALUES
           ($1,$2,$3)

           RETURNING
             id,
             name,
             email,
             role,
             wallet_balance,
             subscribed`,
          [
            String(name).trim(),
            cleanEmail,
            hash
          ]
        );

      const user =
        result.rows[0];

      res.status(201).json({
        user,
        token:
          createToken(user)
      });

    } catch (error) {
      console.error(error);

      if (error.code === '23505') {
        return res.status(409).json({
          error:
            'البريد الإلكتروني مستخدم بالفعل'
        });
      }

      res.status(500).json({
        error: 'تعذر إنشاء الحساب'
      });
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  '/api/auth/login',
  async (req, res) => {
    try {
      const {
        email,
        password
      } = req.body;

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            'البريد وكلمة المرور مطلوبان'
        });
      }

      const cleanEmail =
        String(email)
          .trim()
          .toLowerCase();

      const result =
        await db(
          `SELECT *
           FROM users
           WHERE email = $1`,
          [cleanEmail]
        );

      const user =
        result.rows[0];

      if (
        !user ||
        !(await bcrypt.compare(
          password,
          user.password_hash
        ))
      ) {
        return res.status(401).json({
          error:
            'البريد أو كلمة المرور غير صحيحة'
        });
      }

      res.json({
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          wallet_balance:
            user.wallet_balance,
          subscribed:
            user.subscribed
        },

        token:
          createToken(user)
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'حدث خطأ أثناء تسجيل الدخول'
      });
    }
  }
);

/* =========================
   CURRENT USER
========================= */

app.get(
  '/api/me',
  auth,
  async (req, res) => {
    try {
      const result =
        await db(
          `SELECT
             id,
             name,
             email,
             role,
             wallet_balance,
             subscribed
           FROM users
           WHERE id = $1`,
          [req.user.id]
        );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: 'المستخدم غير موجود'
        });
      }

      res.json(
        result.rows[0]
      );

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'تعذر تحميل بيانات المستخدم'
      });
    }
  }
);

/* =========================
   LESSON DETAILS
========================= */

app.get(
  '/api/courses/:slug/lessons/:lessonId',
  auth,
  async (req, res) => {
    try {
      const result =
        await db(
          `SELECT
             l.*,
             q.id AS quiz_id,
             q.passing_score

           FROM lessons l

           JOIN courses c
             ON c.id = l.course_id

           LEFT JOIN quizzes q
             ON q.lesson_id = l.id

           WHERE c.slug = $1
           AND l.id = $2
           AND l.is_published = true
           AND c.is_published = true`,
          [
            req.params.slug,
            req.params.lessonId
          ]
        );

      if (!result.rows[0]) {
        return res.status(404).json({
          error:
            'الدرس غير موجود'
        });
      }

      res.json(
        result.rows[0]
      );

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'تعذر تحميل الدرس'
      });
    }
  }
);

/* =========================
   GET QUIZ
========================= */

app.get(
  '/api/lessons/:lessonId/quiz',
  auth,
  async (req, res) => {
    try {
      const quizResult =
        await db(
          `SELECT *
           FROM quizzes
           WHERE lesson_id = $1`,
          [req.params.lessonId]
        );

      if (!quizResult.rows[0]) {
        return res.status(404).json({
          error:
            'لا يوجد اختبار لهذا الدرس'
        });
      }

      const quiz =
        quizResult.rows[0];

      const questionsResult =
        await db(
          `SELECT
             id,
             question,
             option_a,
             option_b,
             option_c,
             option_d,
             sort_order

           FROM quiz_questions

           WHERE quiz_id = $1

           ORDER BY
             sort_order ASC,
             id ASC`,
          [quiz.id]
        );

      res.json({
        ...quiz,
        questions:
          questionsResult.rows
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'تعذر تحميل الاختبار'
      });
    }
  }
);

/* =========================
   SUBMIT QUIZ
========================= */

app.post(
  '/api/lessons/:lessonId/quiz/submit',
  auth,
  async (req, res) => {
    try {
      const {
        answers = {}
      } = req.body;

      const quizResult =
        await db(
          `SELECT *
           FROM quizzes
           WHERE lesson_id = $1`,
          [req.params.lessonId]
        );

      if (!quizResult.rows[0]) {
        return res.status(404).json({
          error:
            'لا يوجد اختبار لهذا الدرس'
        });
      }

      const quiz =
        quizResult.rows[0];

      const questionsResult =
        await db(
          `SELECT *
           FROM quiz_questions
           WHERE quiz_id = $1
           ORDER BY
             sort_order ASC,
             id ASC`,
          [quiz.id]
        );

      const questions =
        questionsResult.rows;

      let correct = 0;

      const results =
        questions.map(
          (question) => {

            const selected =
              String(
                answers[
                  question.id
                ] || ''
              ).toUpperCase();

            const correctOption =
              String(
                question.correct_option
              ).toUpperCase();

            const isCorrect =
              selected ===
              correctOption;

            if (isCorrect) {
              correct++;
            }

            return {
              id: question.id,

              selected,

              correct_option:
                correctOption,

              explanation:
                question.explanation,

              correct:
                isCorrect
            };
          }
        );

      const total =
        questions.length;

      const score =
        total > 0
          ? Math.round(
              (correct / total) *
              100
            )
          : 0;

      const passingScore =
        Number(
          quiz.passing_score
        );

      const passed =
        score >=
        passingScore;

      await db(
        `INSERT INTO lesson_progress
         (
           user_id,
           lesson_id,
           completed,
           score,
           attempts,
           last_attempt_at
         )

         VALUES
         (
           $1,
           $2,
           $3,
           $4,
           1,
           NOW()
         )

         ON CONFLICT
         (
           user_id,
           lesson_id
         )

         DO UPDATE SET
           completed =
             EXCLUDED.completed,

           score =
             EXCLUDED.score,

           attempts =
             lesson_progress.attempts + 1,

           last_attempt_at =
             NOW()`,
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
        passing_score:
          passingScore,
        total,
        correct,
        results
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'تعذر تصحيح الاختبار'
      });
    }
  }
);

/* =========================
   STUDENT DASHBOARD
========================= */

app.get(
  '/api/dashboard',
  auth,
  async (req, res) => {
    try {
      const userResult =
        await db(
          `SELECT
             id,
             name,
             email,
             wallet_balance,
             subscribed
           FROM users
           WHERE id = $1`,
          [req.user.id]
        );

      const user =
        userResult.rows[0];

      if (!user) {
        return res.status(404).json({
          error:
            'المستخدم غير موجود'
        });
      }

      const progressResult =
        await db(
          `SELECT
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

           WHERE
             c.is_published = true
             AND l.is_published = true

           ORDER BY
             c.sort_order ASC,
             l.sort_order ASC,
             l.id ASC`,
          [req.user.id]
        );

      const lessons =
        progressResult.rows;

      const completedLessons =
        lessons.filter(
          lesson =>
            lesson.completed === true
        );

      const scores =
        lessons
          .filter(
            lesson =>
              lesson.score !== null
          )
          .map(
            lesson =>
              Number(
                lesson.score
              )
          );

      const averageScore =
        scores.length > 0
          ? Math.round(
              scores.reduce(
                (sum, score) =>
                  sum + score,
                0
              ) /
              scores.length
            )
          : 0;

      res.json({
        user,

        progress: {
          totalLessons:
            lessons.length,

          completedLessons:
            completedLessons.length,

          percent:
            lessons.length > 0
              ? Math.round(
                  completedLessons.length /
                  lessons.length *
                  100
                )
              : 0,

          averageScore,

          lastLesson:
            completedLessons.length > 0
              ? completedLessons[
                  completedLessons.length - 1
                ]
              : null,

          lessons
        }
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'تعذر تحميل لوحة الطالب'
      });
    }
  }
);

/* =========================
   SUBSCRIBE
========================= */

app.post(
  '/api/subscribe',
  auth,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      await client.query(
        'BEGIN'
      );

      const priceResult =
        await client.query(
          `SELECT
             subscription_price
           FROM site_settings
           WHERE id = 1`
        );

      const price =
        Number(
          priceResult.rows[0]
            ?.subscription_price || 0
        );

      const userResult =
        await client.query(
          `SELECT
             wallet_balance,
             subscribed
           FROM users
           WHERE id = $1
           FOR UPDATE`,
          [req.user.id]
        );

      if (!userResult.rows[0]) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'المستخدم غير موجود'
        });
      }

      const user =
        userResult.rows[0];

      if (user.subscribed) {
        await client.query(
          'COMMIT'
        );

        return res.json({
          subscribed: true
        });
      }

      if (
        Number(
          user.wallet_balance
        ) < price
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(400).json({
          error:
            `الرصيد غير كافٍ. سعر الاشتراك ${price}`
        });
      }

      await client.query(
        `UPDATE users
         SET
           wallet_balance =
             wallet_balance - $1,

           subscribed = true

         WHERE id = $2`,
        [
          price,
          req.user.id
        ]
      );

      await client.query(
        `INSERT INTO wallet_transactions
         (
           user_id,
           amount,
           type,
           note
         )
         VALUES
         (
           $1,
           $2,
           'subscription',
           $3
         )`,
        [
          req.user.id,
          -price,
          'اشتراك جميع الكورسات'
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        subscribed: true
      });

    } catch (error) {

      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(error);

      res.status(500).json({
        error:
          'تعذر تنفيذ الاشتراك'
      });

    } finally {
      client.release();
    }
  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  '/api/admin/users',
  auth,
  admin,
  async (req, res) => {
    try {

      const result =
        await db(
          `SELECT
             id,
             name,
             email,
             role,
             wallet_balance,
             subscribed,
             created_at

           FROM users

           ORDER BY
             id DESC`
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'تعذر تحميل الطلاب'
      });
    }
  }
);

/* =========================
   ADMIN CREDIT
========================= */

app.post(
  '/api/admin/users/:id/credit',
  auth,
  admin,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const amount =
        Number(
          req.body.amount
        );

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          error:
            'قيمة الرصيد غير صحيحة'
        });
      }

      await client.query(
        'BEGIN'
      );

      const userResult =
        await client.query(
          `SELECT id
           FROM users
           WHERE id = $1
           FOR UPDATE`,
          [req.params.id]
        );

      if (!userResult.rows[0]) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'الطالب غير موجود'
        });
      }

      await client.query(
        `UPDATE users
         SET
           wallet_balance =
             wallet_balance + $1
         WHERE id = $2`,
        [
          amount,
          req.params.id
        ]
      );

      await client.query(
        `INSERT INTO wallet_transactions
         (
           user_id,
           amount,
           type,
           note
         )
         VALUES
         (
           $1,
           $2,
           'credit',
           $3
         )`,
        [
          req.params.id,
          amount,
          req.body.note ||
            'إضافة رصيد من الإدارة'
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true
      });

    } catch (error) {

      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(error);

      res.status(500).json({
        error:
          'تعذر إضافة الرصيد'
      });

    } finally {
      client.release();
    }
  }
);

/* =========================
   ADMIN SETTINGS
========================= */

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

      const result =
        await db(
          `UPDATE site_settings
           SET
             site_name = $1,
             tagline = $2,
             subscription_price = $3,
             hero_title = $4,
             hero_text = $5

           WHERE id = 1

           RETURNING *`,
          [
            site_name,
            tagline,
            Number(
              subscription_price
            ) || 0,
            hero_title,
            hero_text
          ]
        );

      res.json(
        result.rows[0]
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'تعذر حفظ إعدادات الموقع'
      });
    }
  }
);

/* =========================
   ADMIN CREATE COURSE
========================= */

app.post(
  '/api/admin/courses',
  auth,
  admin,
  async (req, res) => {

    try {

      const {
        title,
        slug,
        description = '',
        image_url = '',
        sort_order = 0
      } = req.body;

      if (!title || !slug) {
        return res.status(400).json({
          error:
            'اسم الكورس والـ slug مطلوبان'
        });
      }

      const result =
        await db(
          `INSERT INTO courses
           (
             title,
             slug,
             description,
             image_url,
             sort_order
           )
           VALUES
           ($1,$2,$3,$4,$5)

           RETURNING *`,
          [
            title,
            slug,
            description,
            image_url,
            Number(sort_order) || 0
          ]
        );

      res.status(201).json(
        result.rows[0]
      );

    } catch (error) {

      console.error(error);

      if (
        error.code === '23505'
      ) {
        return res.status(409).json({
          error:
            'هذا الـ slug مستخدم بالفعل'
        });
      }

      res.status(500).json({
        error:
          'تعذر إنشاء الكورس'
      });
    }
  }
);

/* =========================
   ADMIN CREATE LESSON
========================= */

app.post(
  '/api/admin/lessons',
  auth,
  admin,
  async (req, res) => {

    try {

      const {
        course_id,
        title,
        description = '',
        video_url = '',
        pdf_url = '',
        sort_order = 0
      } = req.body;

      if (
        !course_id ||
        !title
      ) {
        return res.status(400).json({
          error:
            'الكورس واسم الدرس مطلوبان'
        });
      }

      const result =
        await db(
          `INSERT INTO lessons
           (
             course_id,
             title,
             description,
             video_url,
             pdf_url,
             sort_order
           )
           VALUES
           ($1,$2,$3,$4,$5,$6)

           RETURNING *`,
          [
            course_id,
            title,
            description,
            video_url,
            pdf_url,
            Number(sort_order) || 0
          ]
        );

      res.status(201).json(
        result.rows[0]
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          'تعذر إنشاء الدرس'
      });
    }
  }
);

/* =========================
   ADMIN CREATE / UPDATE QUIZ
========================= */

app.post(
  '/api/admin/quizzes',
  auth,
  admin,
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const {
        lesson_id,
        passing_score = 50,
        questions = []
      } = req.body;

      if (!lesson_id) {
        return res.status(400).json({
          error:
            'lesson_id مطلوب'
        });
      }

      if (
        !Array.isArray(
          questions
        )
      ) {
        return res.status(400).json({
          error:
            'questions يجب أن تكون قائمة'
        });
      }

      const pass =
        Number(passing_score);

      if (
        !Number.isFinite(pass) ||
        pass < 0 ||
        pass > 100
      ) {
        return res.status(400).json({
          error:
            'نسبة النجاح يجب أن تكون بين 0 و100'
        });
      }

      await client.query(
        'BEGIN'
      );

      const quizResult =
        await client.query(
          `INSERT INTO quizzes
           (
             lesson_id,
             passing_score
           )
           VALUES
           ($1,$2)

           ON CONFLICT(lesson_id)
           DO UPDATE SET
             passing_score =
               EXCLUDED.passing_score

           RETURNING id`,
          [
            lesson_id,
            pass
          ]
        );

      const quiz =
        quizResult.rows[0];

      await client.query(
        `DELETE FROM quiz_questions
         WHERE quiz_id = $1`,
        [quiz.id]
      );

      for (
        let i = 0;
        i < questions.length;
        i++
      ) {

        const q =
          questions[i];

        const correct =
          String(
            q.correct_option || ''
          ).toUpperCase();

        if (
          !['A','B','C','D']
            .includes(correct)
        ) {
          throw new Error(
            `إجابة صحيحة غير صالحة في السؤال رقم ${i + 1}`
          );
        }

        await client.query(
          `INSERT INTO quiz_questions
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
             $1,$2,$3,$4,$5,$6,$7,$8,$9
           )`,
          [
            quiz.id,
            q.question || '',
            q.option_a || '',
            q.option_b || '',
            q.option_c || '',
            q.option_d || '',
            correct,
            q.explanation || '',
            i
          ]
        );
      }

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,
        quiz_id:
          quiz.id
      });

    } catch (error) {

      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(error);

      res.status(500).json({
        error:
          error.message ||
          'تعذر حفظ الاختبار'
      });

    } finally {
      client.release();
    }
  }
);

/* =========================
   DATABASE INIT
========================= */

async function initDatabase() {

  const schemaPath =
    path.join(
      __dirname,
      'schema.sql'
    );

  if (
    !fs.existsSync(
      schemaPath
    )
  ) {
    throw new Error(
      'schema.sql غير موجود في جذر المشروع'
    );
  }

  const schema =
    fs.readFileSync(
      schemaPath,
      'utf8'
    );

  /*
   * schema.sql الحالي عبارة عن
   * أوامر SQL منفصلة بفواصل ;
   */
  const statements =
    schema
      .split(';')
      .map(
        statement =>
          statement.trim()
      )
      .filter(Boolean);

  for (
    const statement of statements
  ) {
    await db(statement);
  }

  /* =========================
     CREATE / UPDATE ADMIN
  ========================= */

  const adminEmail =
    process.env.ADMIN_EMAIL;

  const adminPassword =
    process.env.ADMIN_PASSWORD;

  if (
    adminEmail &&
    adminPassword
  ) {

    const cleanEmail =
      String(
        adminEmail
      )
        .trim()
        .toLowerCase();

    const hash =
      await bcrypt.hash(
        adminPassword,
        10
      );

    await db(
      `INSERT INTO users
       (
         name,
         email,
         password_hash,
         role
       )
       VALUES
       (
         $1,
         $2,
         $3,
         'admin'
       )

       ON CONFLICT(email)
       DO UPDATE SET

         role = 'admin',

         password_hash =
           EXCLUDED.password_hash`,
      [
        'Administrator',
        cleanEmail,
        hash
      ]
    );

    console.log(
      `Admin account ready: ${cleanEmail}`
    );
  }

  console.log(
    'Database initialization completed.'
  );
}

/* =========================
   API 404
========================= */

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      error:
        'API endpoint not found'
    });
  }
);

/* =========================
   FRONTEND
========================= */

/*
 * مهم:
 * index.html موجود في جذر المشروع
 * وليس داخل public.
 *
 * Express 5 يستخدم /{*splat}
 * بدلاً من '*'
 */
app.get(
  '/{*splat}',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    );
  }
);

/* =========================
   START
========================= */

async function startServer() {

  try {

    await initDatabase();

    await db(
      'SELECT 1'
    );

    app.listen(
      PORT,
      '0.0.0.0',
      () => {

        console.log(
          `StudyMedSmart running on port ${PORT}`
        );

      }
    );

  } catch (error) {

    console.error(
      'SERVER STARTUP FAILED:',
      error
    );

    process.exit(1);
  }
}

startServer();
