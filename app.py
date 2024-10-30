from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template, flash
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from db import Database
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 1800
app.config['WTF_CSRF_ENABLED'] = True

csrf = CSRFProtect(app)

dsn = os.getenv("DATABASE_URL")
db = Database(dsn)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    print("CSRF Token in session:", session.get('_csrf_token'))
    return f"CSRF error: {e.description}", 400


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if db.register_user(username, password):
            flash("Registration successful. Please log in.")
            return redirect(url_for('login'))
        else:
            flash("Username already exists, please choose another one.")
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.login_user(username, password)
        if user is not None:
            session['user_id'] = user[0]
            session['role'] = user[2]
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Please try again.")
    return render_template('login.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_id = session['user_id']
    user_role = session.get('role', 'user')
    if request.method == 'POST':
        content = request.form['content']
        db.add_note(user_id, content)
    notes = db.get_user_notes(user_id)
    return render_template('dashboard.html', notes=notes, user_role=user_role)


@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
    user_id = session['user_id']
    user_role = session.get('role', 'user')
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        db.add_post(user_id, title, content)
    all_posts = db.get_all_posts(include_hidden=(user_role == 'admin'))
    return render_template('post.html', posts=all_posts)


@app.route('/admin/posts', methods=['GET', 'POST'])
@login_required
def admin_posts():
    user_role = session.get('role')
    if user_role != 'admin':
        return "Unauthorized", 403

    if request.method == 'POST':
        post_id = request.form['post_id']
        visibility = request.form['visibility'] == '1'
        try:
            db.set_post_visibility(post_id, visibility, user_role)
        except PermissionError as e:
            return str(e), 403
        except Exception as e:
            return "An error occurred while updating post visibility.", 500
    all_posts = db.get_all_posts(include_hidden=True)
    return render_template('admin_posts.html', posts=all_posts)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    user_id = session['user_id']
    user_role = session.get('role', 'user')
    if not db.is_post_owner(user_id, post_id, user_role):
        return "Unauthorized", 403
    db.delete_post(post_id)
    return redirect(url_for('posts'))

@app.route('/delete_note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    user_id = session['user_id']
    if not db.is_note_owner(user_id, note_id):
        return "Unauthorized", 403
    db.delete_note(note_id)
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.errorhandler(400)
def bad_request(error):
    return f"Bad Request: {error}", 400

if __name__ == '__main__':
    app.run(port=5000)