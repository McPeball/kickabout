import sqlite3
import time
from flask import Flask, render_template, request, url_for, flash, redirect, make_response
from werkzeug.exceptions import abort
from hashlib import sha256
import json
import urllib3
#import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
#import seaborn as sb

# football API parameters
competition = "PL"
#competition = "ELC"
token = 'a69bfd1640b141c2b5846be23e97a08b'
#season_filter = "?season=2020"
season_filter = "?season=2021"



# function to query football API
http = urllib3.PoolManager()
def get_data(query, token):
    r = http.request('GET', 'api.football-data.org' + query, headers = { 'X-Auth-Token': token })
    return(json.loads(r.data))

# connect to SQL db
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

@app.route("/test_API", methods=('GET', 'POST'))
def test_API():
    teams = get_data(f"/v2/competitions/{competition}/teams{season_filter}", token)
    #matches = (get_data(f'/v2/competitions/{competition}/matches{season_filter}', token))
    teams_df = pd.json_normalize(teams, record_path =['teams'])
    return render_template('test_API.html', tables=[teams_df.to_html(classes='data')], titles=teams_df.columns.values)
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

        conn = get_db_connection()
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()

        username_in_db = row[1]
        pw_hash_in_db = row[3]
        salt = row[4]
        current_cookie = row[5]
        pw_hash = sha256((salt + password).encode('utf-8')).hexdigest()
        if pw_hash_in_db == pw_hash:
            resp = make_response(render_template('index.html'))
            resp.set_cookie('username', username_in_db)
            resp.set_cookie('current_cookie', current_cookie)
            flash('login successful')
            return resp
        else:
            flash('login failed. Please try again')
            return render_template('sign_in.html')
