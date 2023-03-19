import sqlite3
import time
from flask import Flask, render_template, request, url_for, flash, redirect, make_response
from werkzeug.exceptions import abort
from hashlib import sha256

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

app = Flask(__name__)

app.config['SECRET_KEY'] = '__sdgjdfsjvdshjer__'

@app.route("/")
def index():
   return render_template('index.html')

@app.route("/testing", methods=('GET', 'POST'))
def testing():
    if request.method == 'POST':
        bobby = request.form['bobby']
        return '<h1>Welcome '+bobby+'</h1>'
    else:
        return render_template('test.html')


@app.route("/sign_up", methods=('GET', 'POST'))
def sign_up():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_check = request.form['password_check']
        salt = sha256(str(time.time()).encode('utf-8')).hexdigest()

        conn = get_db_connection()
        users = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close

        if users == username:
            flash('user already exists')
        elif password != password_check:
            flash('password entries do not match')
        else:
            pw_hash = sha256((salt + password).encode('utf-8')).hexdigest()
            current_cookie = sha256((salt + password + str(time.time())).encode('utf-8')).hexdigest()
            conn = get_db_connection()
            #conn = sqlite3.connect('database.db')
            conn.execute("INSERT INTO users (username, email, salt, pw_hash, current_cookie) VALUES (?, ?, ?, ?, ?)",
                (username, email, salt, pw_hash, current_cookie))
            conn.commit()
            conn.close()


        flash('new user created')
        return render_template('index.html')
    else:
        return render_template('create_user.html')


@app.route("/sign_in", methods=("GET", "POST"))
def sign_in():
    if request.method == 'GET':
        return render_template('sign_in.html')
    else:
        username = request.form['username']
        password = request.form['password']

        return render_template('sign_in.html')