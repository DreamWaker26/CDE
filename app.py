import os
from flask import Flask, flash, render_template, request, redirect, url_for, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from datetime import datetime

UPLOAD_FOLDER = '/home/duncan/CDE/static/img'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

app = Flask(__name__)
app.config['SECRET_KEY'] = 'T0P_S3cRet'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/duncan/CDE/picbook.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
#user information database
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#define form item
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route("/<path:filename>")
def template(filename):
    return render_template(filename)
#index page 
@app.route('/')
def index():
	posts = pic.query.order_by(pic.date_posted.desc()).all()

	return render_template('index.html', posts=posts)
#looged-in index page
@app.route('/index_in')
def index_in():
    posts = pic.query.order_by(pic.date_posted.desc()).all()

    return render_template('index_in.html', posts=posts)
#login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                session['name'] = form.username.data
                return redirect(url_for('index_in'))
            else:
                error = 'Invalid password'
            return render_template('login.html', error=error, form=form)
        else:
            error = 'Invalid username/password'
        return render_template('login.html', error=error, form=form)
        #show error message 

    return render_template('login.html', form=form)
#sign up page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    notice = None

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        notice = 'New user has been created'

        return render_template('signup.html', form=form, notice=notice)
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)
 #logput    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('name', None)
    return redirect(url_for('index'))

#picture database
class pic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    keyword = db.Column(db.String(50))
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    content = db.Column(db.Text)
    picture = db.Column(db.Text(50))

#add picture page
@app.route('/add')
@login_required
def add():
    return render_template('add.html')
#show picture
@app.route('/post/<int:post_id>')
def post(post_id):
    post = pic.query.filter_by(id=post_id).one()

    return render_template('post.html', post=post)
#upload function
@app.route('/addpost', methods=['POST'])
@login_required
def addpost():

	if request.method == "POST":

	    title = request.form['title']
	    keyword = request.form['keyword']
	    author = request.form['author']
	    content = request.form['content']
	    picture = request.files['picture']
	    
	    if picture and allowed_file(picture.filename):
	            #filename = secure_filename(file.filename)
	            filename = picture.filename
	            picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

	    post = pic(title=title, picture=picture.filename, keyword=keyword, author=author, content=content, date_posted=datetime.now())
		
	    db.session.add(post)
	    db.session.commit()
		
	    return redirect(request.referrer)

#debug & redirect port to 8080
if __name__ == '__main__':
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run("0.0.0.0", 8080, debug=True)
