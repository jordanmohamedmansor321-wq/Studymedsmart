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
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized:false } : false });

app.use(express.json({limit:'1mb'}));
app.use(express.static(path.join(__dirname,'public')));

async function db(sql, params=[]) { return pool.query(sql, params); }
function token(user){ return jwt.sign({id:user.id, role:user.role}, JWT_SECRET, {expiresIn:'7d'}); }
function auth(req,res,next){
  try { const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) return res.status(401).json({error:'تسجيل الدخول مطلوب'}); req.user=jwt.verify(h.slice(7),JWT_SECRET); next(); }
  catch { res.status(401).json({error:'جلسة الدخول غير صالحة'}); }
}
function admin(req,res,next){ if(req.user?.role!=='admin') return res.status(403).json({error:'غير مصرح'}); next(); }

app.get('/healthz',(req,res)=>res.json({ok:true}));
app.get('/api/settings', async (req,res)=>{ try{const r=await db('SELECT * FROM site_settings WHERE id=1');res.json(r.rows[0]);}catch(e){res.status(500).json({error:e.message});} });
app.get('/api/courses', async (req,res)=>{ try{const r=await db('SELECT * FROM courses WHERE is_published=true ORDER BY sort_order,id');res.json(r.rows);}catch(e){res.status(500).json({error:e.message});} });
app.get('/api/courses/:slug', async (req,res)=>{ try{const c=await db('SELECT * FROM courses WHERE slug=$1 AND is_published=true',[req.params.slug]); if(!c.rows[0])return res.status(404).json({error:'الكورس غير موجود'}); const l=await db('SELECT l.*,q.id quiz_id,q.passing_score FROM lessons l LEFT JOIN quizzes q ON q.lesson_id=l.id WHERE l.course_id=$1 AND l.is_published=true ORDER BY l.sort_order,l.id',[c.rows[0].id]);res.json({...c.rows[0],lessons:l.rows});}catch(e){res.status(500).json({error:e.message});} });

app.post('/api/auth/register', async(req,res)=>{try{const {name,email,password}=req.body;if(!name||!email||!password||password.length<6)return res.status(400).json({error:'أدخل الاسم والبريد وكلمة مرور 6 أحرف على الأقل'});const hash=await bcrypt.hash(password,10);const r=await db('INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email,role,wallet_balance,subscribed',[name,email.toLowerCase(),hash]);res.json({user:r.rows[0],token:token(r.rows[0])});}catch(e){res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'البريد مستخدم بالفعل':e.message});}});
app.post('/api/auth/login', async(req,res)=>{try{const {email,password}=req.body;const r=await db('SELECT * FROM users WHERE email=$1',[email.toLowerCase()]);if(!r.rows[0]||!(await bcrypt.compare(password,r.rows[0].password_hash)))return res.status(401).json({error:'البريد أو كلمة المرور غير صحيحة'});const u=r.rows[0];res.json({user:{id:u.id,name:u.name,email:u.email,role:u.role,wallet_balance:u.wallet_balance,subscribed:u.subscribed},token:token(u)});}catch(e){res.status(500).json({error:e.message});}});
app.get('/api/me',auth,async(req,res)=>{try{const r=await db('SELECT id,name,email,role,wallet_balance,subscribed FROM users WHERE id=$1',[req.user.id]);res.json(r.rows[0]);}catch(e){res.status(500).json({error:e.message});}});

app.get('/api/courses/:slug/lessons/:lessonId',auth,async(req,res)=>{try{const r=await db('SELECT l.*,q.id quiz_id,q.passing_score FROM lessons l LEFT JOIN quizzes q ON q.lesson_id=l.id JOIN courses c ON c.id=l.course_id WHERE c.slug=$1 AND l.id=$2 AND l.is_published=true',[req.params.slug,req.params.lessonId]);if(!r.rows[0])return res.status(404).json({error:'الدرس غير موجود'});res.json(r.rows[0]);}catch(e){res.status(500).json({error:e.message});}});
app.get('/api/lessons/:lessonId/quiz',auth,async(req,res)=>{try{const q=await db('SELECT * FROM quizzes WHERE lesson_id=$1',[req.params.lessonId]);if(!q.rows[0])return res.status(404).json({error:'لا يوجد اختبار'});const x=await db('SELECT id,question,option_a,option_b,option_c,option_d,sort_order FROM quiz_questions WHERE quiz_id=$1 ORDER BY sort_order,id',[q.rows[0].id]);res.json({...q.rows[0],questions:x.rows});}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/lessons/:lessonId/quiz/submit',auth,async(req,res)=>{try{const {answers={}}=req.body;const q=await db('SELECT * FROM quizzes WHERE lesson_id=$1',[req.params.lessonId]);if(!q.rows[0])return res.status(404).json({error:'لا يوجد اختبار'});const qs=await db('SELECT * FROM quiz_questions WHERE quiz_id=$1 ORDER BY sort_order,id',[q.rows[0].id]);let correct=0;const results=qs.rows.map(x=>{const selected=(answers[x.id]||'').toUpperCase();const ok=selected===x.correct_option;if(ok)correct++;return {id:x.id,selected,correct_option:x.correct_option,explanation:x.explanation,correct:ok};});const score=qs.rows.length?Math.round(correct/qs.rows.length*100):0;const passed=score>=q.rows[0].passing_score;await db(`INSERT INTO lesson_progress(user_id,lesson_id,completed,score,attempts,last_attempt_at) VALUES($1,$2,$3,$4,1,NOW()) ON CONFLICT(user_id,lesson_id) DO UPDATE SET completed=EXCLUDED.completed,score=EXCLUDED.score,attempts=lesson_progress.attempts+1,last_attempt_at=NOW()`,[req.user.id,req.params.lessonId,passed,score]);res.json({score,passed,passing_score:q.rows[0].passing_score,total:qs.rows.length,correct,results});}catch(e){res.status(500).json({error:e.message});}});

app.get('/api/dashboard',auth,async(req,res)=>{try{const u=(await db('SELECT id,name,email,wallet_balance,subscribed FROM users WHERE id=$1',[req.user.id])).rows[0];const p=await db(`SELECT l.id,l.title,c.title course_title,lp.completed,lp.score,lp.last_attempt_at FROM lessons l JOIN courses c ON c.id=l.course_id LEFT JOIN lesson_progress lp ON lp.lesson_id=l.id AND lp.user_id=$1 WHERE c.is_published=true AND l.is_published=true ORDER BY c.sort_order,l.sort_order,l.id`,[req.user.id]);const rows=p.rows;const completed=rows.filter(x=>x.completed).length;const scores=rows.filter(x=>x.score!=null).map(x=>Number(x.score));res.json({user:u,progress:{totalLessons:rows.length,completedLessons:completed,percent:rows.length?Math.round(completed/rows.length*100):0,averageScore:scores.length?Math.round(scores.reduce((a,b)=>a+b,0)/scores.length):0,lastLesson:rows.filter(x=>x.completed).at(-1)||null,lessons:rows}});}catch(e){res.status(500).json({error:e.message});}});

app.post('/api/subscribe',auth,async(req,res)=>{try{const price=Number((await db('SELECT subscription_price FROM site_settings WHERE id=1')).rows[0].subscription_price);const u=(await db('SELECT wallet_balance,subscribed FROM users WHERE id=$1',[req.user.id])).rows[0];if(u.subscribed)return res.json({subscribed:true});if(Number(u.wallet_balance)<price)return res.status(400).json({error:`الرصيد غير كافٍ. سعر الاشتراك ${price}`});await db('BEGIN');await db('UPDATE users SET wallet_balance=wallet_balance-$1,subscribed=true WHERE id=$2',[price,req.user.id]);await db('INSERT INTO wallet_transactions(user_id,amount,type,note) VALUES($1,$2,\'subscription\',$3)',[req.user.id,-price,'اشتراك جميع الكورسات']);await db('COMMIT');res.json({subscribed:true});}catch(e){try{await db('ROLLBACK')}catch{}res.status(500).json({error:e.message});}});

app.get('/api/admin/users',auth,admin,async(req,res)=>{const r=await db('SELECT id,name,email,role,wallet_balance,subscribed,created_at FROM users ORDER BY id DESC');res.json(r.rows);});
app.post('/api/admin/users/:id/credit',auth,admin,async(req,res)=>{try{const amount=Number(req.body.amount);if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({error:'قيمة غير صحيحة'});await db('UPDATE users SET wallet_balance=wallet_balance+$1 WHERE id=$2',[amount,req.params.id]);await db('INSERT INTO wallet_transactions(user_id,amount,type,note) VALUES($1,$2,\'credit\',$3)',[req.params.id,amount,req.body.note||'إضافة رصيد من الإدارة']);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.put('/api/admin/settings',auth,admin,async(req,res)=>{try{const {site_name,tagline,subscription_price,hero_title,hero_text}=req.body;const r=await db('UPDATE site_settings SET site_name=$1,tagline=$2,subscription_price=$3,hero_title=$4,hero_text=$5 WHERE id=1 RETURNING *',[site_name,tagline,subscription_price,hero_title,hero_text]);res.json(r.rows[0]);}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/admin/courses',auth,admin,async(req,res)=>{try{const {title,slug,description,image_url,sort_order=0}=req.body;const r=await db('INSERT INTO courses(title,slug,description,image_url,sort_order) VALUES($1,$2,$3,$4,$5) RETURNING *',[title,slug,description||'',image_url||'',sort_order]);res.json(r.rows[0]);}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/admin/lessons',auth,admin,async(req,res)=>{try{const {course_id,title,description,video_url,pdf_url,sort_order=0}=req.body;const r=await db('INSERT INTO lessons(course_id,title,description,video_url,pdf_url,sort_order) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[course_id,title,description||'',video_url||'',pdf_url||'',sort_order]);res.json(r.rows[0]);}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/admin/quizzes',auth,admin,async(req,res)=>{try{const {lesson_id,passing_score=50,questions=[]}=req.body;await db('BEGIN');const q=(await db('INSERT INTO quizzes(lesson_id,passing_score) VALUES($1,$2) ON CONFLICT(lesson_id) DO UPDATE SET passing_score=EXCLUDED.passing_score RETURNING id',[lesson_id,passing_score])).rows[0];await db('DELETE FROM quiz_questions WHERE quiz_id=$1',[q.id]);for(let i=0;i<questions.length;i++){const x=questions[i];await db('INSERT INTO quiz_questions(quiz_id,question,option_a,option_b,option_c,option_d,correct_option,explanation,sort_order) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[q.id,x.question,x.option_a,x.option_b,x.option_c,x.option_d,x.correct_option,x.explanation||'',i]);}await db('COMMIT');res.json({ok:true,quiz_id:q.id});}catch(e){try{await db('ROLLBACK')}catch{}res.status(500).json({error:e.message});}});

async function init(){
  if(!process.env.DATABASE_URL){console.warn('DATABASE_URL is missing');}
  try{const schema=fs.readFileSync(path.join(__dirname,'db/schema.sql'),'utf8');for(const statement of schema.split(';').map(s=>s.trim()).filter(Boolean)) await db(statement);const adminEmail=process.env.ADMIN_EMAIL;const adminPassword=process.env.ADMIN_PASSWORD;if(adminEmail&&adminPassword){const hash=await bcrypt.hash(adminPassword,10);await db(`INSERT INTO users(name,email,password_hash,role) VALUES('Administrator',$1,$2,'admin') ON CONFLICT(email) DO UPDATE SET role='admin'`,[adminEmail.toLowerCase(),hash]);}console.log('Database ready');}catch(e){console.error('DB init failed:',e.message);}
}
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
init().then(()=>app.listen(PORT,()=>console.log(`StudyMedSmart listening on ${PORT}`)));
