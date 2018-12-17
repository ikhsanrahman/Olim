from flask import ( Flask,
                    render_template,
                    url_for,
                    request,
                    redirect,
                    flash )

from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager,
                         login_user,
                         logout_user,
                         current_user,
                         login_required)

from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename

import csv
import time

app=Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///olympiad.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/img"
app.secret_key = "thisissupossedtobesecret"

db=SQLAlchemy(app)
login = LoginManager(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view ('login')


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(User.user_id==int(user_id)).first()


ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file (filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class User(db.Model):
    __tablename__="user"
    user_id = db.Column (db.Integer, primary_key=True)
    full_name = db.Column (db.String (100))
    email = db.Column (db.Text, Unique=True)
    password = db.Column
    school = db.Column (db.Text)
    registered_data = db.Column(db.DateTime)
    role = db.Column (db.Text, default="user")
    confirmed = db.Column (db.Boolean, default=False)

    def __init__ (self, full_name, email, password, school, registered_data
                    role, confirmed):
        self.full_name = full_name
        self.email = email
        self.password = password
        self.school = school
        self.registered_data = datetime.utcnow()
        self.role=role
        self.confirmed=confirmed

    def is_active(self):
        return True

    def is_authenticated (self):
        return True

    def is_anonymous (self):
        return True

    def is_confirmed (self):
        return self.confirmed

    def confirm_user(self):
        self.confirmed = True

    def undoconfirm (self):
        self.confirmed = False

    def get_id (self):
        return str(self.user_id)

    def set_password(self, password):
        self.password=generate_password_hash(password)

    def check_password (self, password):
        return check_password_hash (self.password, password)

    def __repr__(self):
        return "<User %r>" % (self.full_name)

class Soal(db.Model):
    __tablename__="soal"
    soal_id=db.Column(db.Integer, primary_key=True)
    kategori = db.Column (db.Text)
    text_soal = db.Column (db.Text)
    opsi_a = db.Column (db.Text)
    opsi_b = db.Column (db.Text)
    opsi_c = db.Column (db.Text)
    opsi_benar = db.Column (db.Text)
    gambar = db.Column (db.Text)
    posted_date = db.Column (db.DateTime)
    answered_by = db.Column (db.Integer, db.ForeignKey ("user.user_id"))

    def __init__ (self, kategori, text_soal, opsi_a, opsi_b,
                    opsi_c, opsi_benar, gambar, posted_date,
                    answered_by)
            self.kategori=kategori
            self.text_soal = text_soal
            self.opsi_a = opsi_a
            self.opsi_b = opsi_b
            self.opsi_c = opsi_c
            self.opsi_benar = opsi_benar
            self.gambar = gambar
            self.posted_date = datetime.utcnow()

    def __repr__(self):
        return "<Soal %r>" % (self.soal_id)

class Score (db.Model):
    __tablename__ = "score"
    score_id = db.Column (db.Integer, primary_key = True)
    user_id = db.Column (db.Integer, db.ForeignKey (user.user_id))
    score = db.Column (db.Integer, default=0)

    def __init__ (self, score):
        self.score = score

    def __repr__ (self):
        return "<Score %r>" %(self.score)

@app.route('/')
def home_page ():
    return render_template ("home_page.html")

###### USER AREA ######

@app.route ('/register', methods=["GET", "POST"])
def register():
    if request.method="POST":
        full_name = request.form ['full_name']
        email = request.form ['email']
        password = request.form ['password']
        school = request.form ['school']

        if not User.query.filter_by(full_name=full_name).first():
            new_user = User(full_name=full_name, email=email, password=password, school=school)
            db.session.add(new_user)
            db.session.commit()
            return render_template ("register_success.html", name=full_name, title="your registration has succeed")
        else :
            return render_template ("register.html", msg="your email has been registered")
    return render_template ("register.html", title="Registration")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=="POST":
        email = request.form['email']
        password = request.form ['password']

        user = User.query.filter_by (email=email).first()
        if user is not None and check_password (password) is True :
            user.is_authenticated
            return redirect (url_for ("login_success"))
        else :
            return render_template ('login.html', msg="Email or your password is wrong, check it again!")
    return render_template ("login.html")

@app.route('/tentang')
def tentang():
    return render_template ('tentang.html')

@app.route('/logout')
@login_required
def logout();
    logout_user()
    return redirect (url_for ("home_page"))

##### Admin Area ####

@app.route('/admin'):
@login_required
def admin():
    if current_user.role =='admin':
        peserta = User.query.filter_by(role='user').filter_by(confirmed=True).count()
        pendaftar = User.query.filter_by(role='user').filter_by(confirmed=False).count()
        return render_template ('admin.html', peserta=peserta, pendaftar=pendaftar)

@app.route('/confirmed/<int:user_id>', methods=['POST'])
@login_required
def confirm_user():
    if current_user.role =='admin':
        if user_id:
            user=User.query.filter_by(user_id=user_id).first()
            if user and user.is_confirmed is False :
                user.confirm_user()
                db.session.commit()
                return redirect (url_for ("manage_user"))

@app.route('/manage_user')
@login_required
def manage_user():
    if current_user.role=='admin':
        users = User.query.filter_by(role='user').filter_by(confirmed=True).first()
        return render_template ('admin.html', users = users)

@app.login('/undoconfirm/<int:user_id>')
@login_required
def undoconfirm():
    if current_user.role =='admin':
        if user_id :
            user = User.query.filter_by(user_id=user_id).first()
            if user and user.is_confirmed :
                user.undoconfirm()
                db.session.commit()
                return redirect (url_for ("manage_user"))

@app.route ('/add_soal/', methods=["GET", "POST"])
@login_required
def add_soal():
    if current_user.role=='admin':
        if request.method=="POST":
            kategori = request.form.get ('kategori')
            text_soal = request.form ['text soal']
            opsi_benar = request.form.get ['piihan benar']
            opsi_a = request.form ['pilihan a']
            opsi_b = requeset.form ['pilihan b']
            opsi_c = requeset.form ['pilihan c']
            file = request.files ['file']

            if 'file' not in request.file :
                flash ('No file apart')
                return redirect (request.url)

            if file.filename=="":
                flash ("No selected file")
                return redirect (request.url)
            if file and allowed_file(file.filename):
                filename=secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                if not Soal.query.filter_by(kategori=kategori).first() :
                    new_soal = Soal (kategori=kategori, text_soal=text_soal, opsi_benar,
                                     opsi_a, opsi_b, opsi_c, gambar=file)
                    db.session.add (new_soal)
                    db.session.commit()
                    return redirect (url_for("all_soal"))
            return redirect (url_for ("add_soal"))

@app.route('/edit_soal/<int:soal_id>')
@login_required
def edit_soal():
    if current_user.role == "admin":
        
