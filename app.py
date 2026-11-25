import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from google import genai

# تحميل المتغيرات السرية من ملف .env
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or os.urandom(32).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///study_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# إعدادات أمان الجلسات (Cookies Security)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# تفعيل الحمايات
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# تهيئة عميل Gemini API إذا توفر مفتاح
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

# ==================== نماذج قاعدة البيانات (Models) ====================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    exams = db.relationship('Exam', backref='student', lazy=True, cascade="all, delete-orphan")
    notes = db.relationship('Note', backref='author', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Exam(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    exam_date = db.Column(db.String(50), nullable=False)
    study_time = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ==================== رؤوس الأمان (Security Headers) ====================

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ==================== المسارات (Routes) ====================

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    if request.method == 'POST':
        raw_email = (request.form.get('email') or '').replace(' ', '').strip().lower()
        password = request.form.get('password') or ''

        if not raw_email or '@' not in raw_email:
            flash('يرجى إدخال بريد إلكتروني صحيح بدون مسافات.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('كلمة المرور يجب أن تكون 8 أحرف على الأقل لحماية حسابك.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=raw_email).first():
            flash('البريد الإلكتروني مسجل مسبقاً.', 'warning')
            return redirect(url_for('register'))

        new_user = User(email=raw_email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('تم إنشاء الحساب بنجاح! يمكنك تسجيل الدخول الآن.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("15 per minute")
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').replace(' ', '').strip().lower()
        password = request.form.get('password') or ''
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('بيانات الدخول غير صحيحة.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    exams = Exam.query.filter_by(user_id=current_user.id).all()
    notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.created_at.desc()).all()
    return render_template('dashboard.html', exams=exams, notes=notes)

@app.route('/add_exam', methods=['POST'])
@login_required
def add_exam():
    subject = (request.form.get('subject') or '').strip()
    exam_date = (request.form.get('exam_date') or '').strip()
    study_time = (request.form.get('study_time') or 'غير محدد').strip()

    if subject and exam_date:
        exam = Exam(
            subject=subject,
            exam_date=exam_date,
            study_time=study_time,
            user_id=current_user.id
        )
        db.session.add(exam)
        db.session.commit()
        flash('تمت إضافة الامتحان ووقت المراجعة.', 'success')
    else:
        flash('يرجى إدخال اسم المادة وتاريخ الامتحان.', 'warning')
    return redirect(url_for('dashboard'))

@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    title = (request.form.get('title') or '').strip()
    content = (request.form.get('content') or '').strip()

    if title and content:
        note = Note(title=title, content=content, user_id=current_user.id)
        db.session.add(note)
        db.session.commit()
        flash('تم حفظ الملاحظة بنجاح.', 'success')
    else:
        flash('يرجى إدخال عنوان الملاحظة ومحتواها.', 'warning')
    return redirect(url_for('dashboard'))

# ==================== التكامل مع Gemini AI ====================

@app.route('/ask_gemini', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def ask_gemini():
    data = request.get_json(silent=True) or {}
    prompt_type = data.get('type')
    content = (data.get('content') or '').strip()

    if prompt_type == 'schedule':
        exams = Exam.query.filter_by(user_id=current_user.id).all()
        if not exams:
            return jsonify({'error': 'أضف امتحاناً واحداً على الأقل أولاً لتوليد جدول مراجعة.'}), 400
        exams_list = ", ".join([
            f"{e.subject} بتاريخ {e.exam_date} (مراجعة: {e.study_time})"
            for e in exams
        ])
        prompt = (
            f"أنا طالب ولدي الامتحانات التالية: ({exams_list}). "
            "أنشئ لي جدول مراجعة ذكي ومفصل باللغة العربية يوزع الساعات بفعالية مع فترات راحة."
        )
    elif prompt_type == 'summarize':
        if not content:
            return jsonify({'error': 'لا يوجد نص للملاحظة لتلخيصه.'}), 400
        prompt = (
            "لخص لي هذه الملاحظة الدراسية في نقاط مركزة وسهلة الحفظ "
            f"مع استخراج أهم الأسئلة المتوقعة منها:\n\n{content}"
        )
    else:
        if not content:
            return jsonify({'error': 'الطلب فارغ.'}), 400
        prompt = content

    # محاولة الاتصال الفعلي بـ Gemini إذا توفر مفتاح صالح
    current_key = os.getenv('GEMINI_API_KEY')
    if current_key:
        try:
            ai_client = client if client else genai.Client(api_key=current_key)
            response = ai_client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
            )
            if response and response.text:
                return jsonify({'reply': response.text})
        except Exception as e:
            print("Gemini Error:", repr(e))

    # وضع احتياطي محلي يعمل بدون مفتاح API أو عند تعذر الاتصال بـ Gemini
    if prompt_type == 'schedule':
        exams = Exam.query.filter_by(user_id=current_user.id).all()
        lines = ["📌 جدول مراجعة تلقائي (بدون مفتاح API):"]
        for i, e in enumerate(exams, start=1):
            lines.append(
                f"{i}. مادة {e.subject} — موعد الامتحان: {e.exam_date} | وقت المراجعة: {e.study_time}\n"
                f"   • جلسة تركيز (45 دقيقة) + راحة (10 دقائق)\n"
                f"   • مراجعة الأفكار الرئيسية وحل أسئلة تطبيقية."
            )
        return jsonify({'reply': "\n\n".join(lines)})

    if prompt_type == 'summarize':
        parts = [
            p.strip()
            for p in content.replace('؟', '.').replace('!', '.').split('.')
            if p.strip()
        ]
        bullets = "\n".join([f"• {p}" for p in parts[:5]]) or f"• {content[:200]}"
        reply = (
            "📝 تلخيص تلقائي للملاحظة (بدون مفتاح API):\n\n"
            f"{bullets}\n\n"
            "❓ سؤال مراجعة مقترح:\n"
            f"ما أهم فكرة في هذا الدرس ({content[:40]}...)؟"
        )
        return jsonify({'reply': reply})

    return jsonify({'reply': f"تم استلام طلبك (الوضع المحلي): {content}"})

# ==================== التشغيل ====================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)