from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_login import login_user, LoginManager, UserMixin, logout_user, login_required
from sqlalchemy.sql import func



basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir, 'my_first_blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SECRET_KEY"] = 'd0dea8ec6f383438'

db = SQLAlchemy(app)
login_manager = LoginManager(app)


class User (db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100),unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.Text(), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True),
                           server_default=func.now())
    bio = db.Column(db.Text)

    def __repr__(self):
        return f'<User {self.username}>'


@login_manager.user_loader
def user_loader(id):
    return User.query.get(int(id))


@app.route('/')
def index():
    # user = User.query.filter_by('username')
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        username = request.form.get('confirm')

        user = User.query.filter_by(username=username).first()
        if user:
            return redirect(url_for('register'))
        
        email_exists = User.query.filter_by(email=email).first()
        if email_exists:
            return redirect(url_for('register'))


        password_hash = generate_password_hash(password)

        new_user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('signup.html')

  

        

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))




@app.route('/protected')
@login_required
def protected():
    return render_template('protected.html')












if __name__=="__main__":
    app.run(debug=True)




























