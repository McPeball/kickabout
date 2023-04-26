import sqlite3
import time
from flask import Flask, g, render_template, request, url_for, flash, redirect, make_response
from werkzeug.exceptions import abort
from hashlib import sha256
import json
import urllib3
from matplotlib.figure import Figure
import pandas as pd
import base64
from io import BytesIO
from functools import wraps
import smtplib, ssl



token = 'a69bfd1640b141c2b5846be23e97a08b'

''' 

This section contains functions to: 
    get data from the web API
    interact with SQL database

'''

http = urllib3.PoolManager()
def get_data(query, token):
    """creates http request
    Args:
      query: url query string to be attached to the server name
      token: API token obtained from football-data.org
    Returns:
      JSON string
    Raises:
      TypeError: if called  without positional arguments
    """
    r = http.request('GET', 'api.football-data.org' + query, headers = { 'X-Auth-Token': token })
    return(json.loads(r.data))

def make_match_df(competition, season):
    """makes pandas data frame of fixture results
    Args:
      competition: league(PL or ECL)
      season: season (ie 2020 or 2021)
    Returns:
      pandas data frame
    Raises:
      TypeError: if called  without positional arguments
    """
    season_filter = r"?season=" + str(season)
    matches = (get_data(f'/v2/competitions/{competition}/matches{season_filter}', token))
    if matches is None:
        flash("No data was returned from the API")
    matches_df = pd.json_normalize(matches, record_path = ['matches'])
    return matches_df

def get_results_from_API(username, competition, season):
    """formats a pandas data frame of fixtures as one result per team
    Args:
      username: users login name
      competition: league(PL or ECL)
      season: 2020 | 2021 etc.
    Returns:
      Pandas data frame formatted with one team result per row
    Raises:
      TypeError: if called  without positional arguments
    """
    matches_df = make_match_df(competition, season)
    # create a results data frame - accumulate data in a list of lists first
    data_for_results = []
    for index, row in matches_df.iterrows():
        # who won?
        home_team_result = int(0)
        away_team_result = int(0)
        if(row['score.winner'] == 'HOME_TEAM'):
            home_team_result = 1
            away_team_result = -1
        elif(row['score.winner'] == 'AWAY_TEAM'):
            home_team_result = -1
            away_team_result = 1
        # goal_difference?
        home_team_gd = 0
        home_team_gf = 0
        home_team_ga = 0
        away_team_gd = 0
        away_team_gf = 0
        away_team_ga = 0
        if(row['status'] == 'FINISHED'):
            home_team_gd = row['score.fullTime.homeTeam'] - row['score.fullTime.awayTeam']
            home_team_gf = row['score.fullTime.homeTeam']
            home_team_ga = row['score.fullTime.awayTeam']
            away_team_gd = row['score.fullTime.awayTeam'] - row['score.fullTime.homeTeam']
            away_team_gf = row['score.fullTime.awayTeam']
            away_team_ga = row['score.fullTime.homeTeam']
        data_for_results.append([
            username,
            competition,
            season,
            row['matchday'],
            row['status'],
            row['homeTeam.name'],
            row['homeTeam.id'],
            home_team_result,
            home_team_gd,
            home_team_gf,
            home_team_ga,
            'home'
            ])
        data_for_results.append([
            username,
            competition,
            season,
            row['matchday'],
            row['status'],
            row['awayTeam.name'],
            row['awayTeam.id'],
            away_team_result,
            away_team_gd,
            away_team_gf,
            away_team_ga,
            'away'
            ])
    return pd.DataFrame(data_for_results, columns=['username', 'competition', 'season', 'matchday', 'status', 'team_name', 'team_id', 'result', 'gd', 'gf', 'ga', 'home_away'])

def put_results_into_db(username, competition, season):
    """puts results into SQL table
    Args:
      username: users login name
      competition: league(PL or ECL)
      season: 2020 | 2021 etc.
    Returns:
      results table
    Raises:
      TypeError: if called  without positional arguments
    """
    conn = get_db_connection()
    curs = conn.cursor()
    curs.execute("DELETE from matches WHERE username=?", (username,))
    conn.commit()
    conn.close()
    conn = get_db_connection()
    results = get_results_from_API(username, competition, season)
    for index, row in results.iterrows():
        conn.execute('INSERT INTO matches (username, competition, season, matchday, status, team_name, team_id, result, gd, gf, ga, home_away) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (username,
            competition,
            season,
            row['matchday'],
            row['status'],
            row['team_name'],
            row['team_id'],
            row['result'],
            row['gd'],
            row['gf'],
            row['ga'],
            row['home_away'])
            )
    conn.commit()
    conn.close()
    return results

def get_results_from_db(username):
    """gets results table from
    Args:
      username: users login name
    Returns:
      results table
    Raises:
      TypeError: if called  without positional arguments
    """
    # May need to add arguments for competition and season
    conn = get_db_connection()
    curs = conn.cursor()
    matches = curs.execute("SELECT * FROM matches WHERE username=?", (username,)).fetchall()
    conn.close
    #accumulate match data
    data_for_results = []
    for match in matches:
        data_for_results.append([
            username,
            match['competition'],
            match['season'],
            match['matchday'],
            match['status'],
            match['team_name'],
            match['team_id'],
            match['result'],
            match['gd'],
            match['gf'],
            match['ga'],
            match['home_away']
            ])
    results = pd.DataFrame(data_for_results, columns=['username', 'competition', 'season', 'matchday', 'status', 'team_name', 'team_id', 'result', 'gd', 'gf', 'ga', 'home_away'])
    return results

def get_db_connection():
    """establishes connection between SQL database and server.
    Args:
      None
    Returns:
      SQLite3 row_factory connection
    Raises:
      TypeError: if called  without positional arguments
    """
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

''' 

This section contains:
    a function to send an email to a user
    a decorator function to check for a valid cookie to prevent access to restricted pages

'''

def send_email(username, email, cookie):
    """Sends an email to user with verification link
    Args:
      username: users login name
      email: users email address
      cookie: current cookie value stored in database
    Returns:
      N/A
    Raises:
      TypeError: if called  without positional arguments
    """
    # port 465 for SSL
    port = 465
    # app password from google https://myaccount.google.com/apppasswords
    password = "xgdubvfyvwfvqwfv"
    
    # Create a secure SSL context
    context = ssl.create_default_context()
    
    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
        server.login("Kickabout.Development@gmail.com", password)
        sender_email = "Kickabout.development@gmail.com"
        message = """\
Subject: Kickabout

Please verify your kickabout login by clicking the following link.
http://192.168.1.214:5001/verify-email?user={0}&cookie={1}
Thanks, the Kickabout Developer
        """
        server.sendmail(sender_email, email, message.format(username, cookie))

def check_login(f):
    """checks users login matches the original sign up
    Args:
      f: function to be decorated
    Returns:
      sign in request as args and kwargs
    Raises:
      TypeError: if called  without positional arguments
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        """checks username matches and redirects if it doesn't match as args and kwargs
        Args:
          *args:
          **kwargs: key word args
        Returns:
          result from decorated_function, if usernames don't match then the user is redirected back to sign in page
        Raises:
          TypeError: if called  without positional arguments
        """
        if request.cookies.get("username") is None:
            return redirect(url_for('sign_in', next=request.url))
        else:
            username = request.cookies.get('username')
            cookie = request.cookies.get('current_cookie')
            conn = get_db_connection()
            row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            conn.close()
            
            if row is None:
                return redirect(url_for('sign_in', next=request.url))
            username_in_db = row[1]
            current_cookie = row[5]
            if ((current_cookie != cookie) or (username_in_db != username)):
                return redirect(url_for('sign_in', next=request.url))
                
        return f(*args, **kwargs)
    return decorated_function

''' 

This section contains functions used for the main web application

'''

app = Flask(__name__)

app.config['SECRET_KEY'] = '__sdgjdfsjvdshjer__'

@app.route("/", methods=["GET"])
def index():
    """adds new page from index.html
    Args:
      None
    Returns:
      index.html file which renders a new page
    """
    return render_template('index.html')

@app.route("/get_match_data", methods=("POST", "GET"))
@check_login
def get_match_data():
    """makes form collect competition and season
    Args:
      None
    Returns:
      if GET then displays drop down of competition or season, else (POST) displays show_table.html
    """
    if request.method == "GET":
        return render_template("get_data.html")
    else:
        username = request.cookies.get("username")
        competition = request.form["competition"]
        season = request.form["season"]
        results = put_results_into_db(username, competition, season)
        return render_template('show_table.html', tables=[results.to_html(classes='data')], titles=results.columns.values)

@app.route('//select_data_to_show', methods=("GET",))
@check_login
def select_data_to_show():
    """collects teams to plot
    Args:
      None
    Returns:O
      rendered html with teams to plot
    """
    if request.method == "GET":
        # insert webform here:
        # get teams
        username = request.cookies.get("username")

        conn = get_db_connection()
        curs = conn.cursor()
        matches = curs.execute("SELECT * FROM matches WHERE username=?", (username,)).fetchall()
        conn.close
        teams = set()
        for match in matches:
            teams.add(match["team_name"])
        return render_template("select_data_to_show.html", teams=sorted(teams))

@app.route("/show_plot_gd_matchday", methods=("POST", "GET"))
@check_login
def show_plot_gd_matchday():
    """creates matplotlib of goal difference over match days
    Args:
      None
    Returns:
      renders html for show_plot_gd_matchday in base64 format
    """
    teams = request.form.getlist("team")
    username = request.cookies.get("username")
    results = get_results_from_db(username)
    df_for_plot = results[results["team_name"].isin(teams)]

    # Create a figure canvas to hold the plot
    fig = Figure()

    # Add a single Axes object (with x and y axes)
    ax = fig.subplots()

    # for each time, add an x-y scatter plot. Use label=team to identify it for the legend
    for team in teams:
        ax.scatter(df_for_plot.loc[df_for_plot['team_name'] == team, "matchday"], df_for_plot.loc[df_for_plot['team_name'] == team, "gd"], alpha=0.5, label=team)

    # Set the x and y axis labels
    ax.set_xlabel('matchday', fontsize=15)
    ax.set_ylabel('gd', fontsize=15)

    # Add a legend
    ax.legend()

    # makes the plot fit the canvas better
    fig.tight_layout()

    # open a BytesIO buffer object, save the file to the buffer and base64-encode the bytes to ascii
    img = BytesIO()
    fig.savefig(img, format="png")
    data = base64.b64encode(img.getbuffer()).decode("ascii")

    return render_template('show_plot.html', plot_url=data, title="Plot GD across matchdays")


@app.route("/show_plot_gf_ga", methods=('POST', "GET"))
@check_login
def show_plot_gf_ga():
    """creates matplotlib of goals for and against
    Args:
      None
    Returns:
      renders html for show_plot_gf_ga in base64
    """
    teams = request.form.getlist("team")
    competition = request.form["competition"]
    season = request.form["season"]
    username = request.cookies.get("username")
    results = get_results_from_db(username)
    df_for_plot = results[results["team_name"].isin(teams)]
    fig = Figure()
    ax = fig.subplots()
    for team in teams:
        ax.scatter(df_for_plot.loc[df_for_plot['team_name'] == team, "gf"], df_for_plot.loc[df_for_plot['team_name'] == team, "ga"], alpha=0.5, label=team)
    ax.set_xlabel('Goals for', fontsize=15)
    ax.set_ylabel('Goals against', fontsize=15)
    ax.legend()
    fig.tight_layout()
    img = BytesIO()
    fig.savefig(img, format="png")
    data = base64.b64encode(img.getbuffer()).decode("ascii")

    return render_template('show_plot.html', plot_url=data, title="Plot GF and GA")

@app.route("/show_plot_gd_home_away", methods=('POST', "GET"))
@check_login
def show_plot_gd_home_away():
    """creates matplotlib of goal difference home and away
    Args:
      None
    Returns:
      renders html for show_plot_gd_home_away in base64 format
    """
    teams = request.form.getlist("team")
    competition = request.form["competition"]
    season = request.form["season"]
    username = request.cookies.get("username")
    results = get_results_from_db(username)
    df_for_plot = results[results["team_name"].isin(teams)]
    fig = Figure()
    ax = fig.subplots()
    for team in teams:
        ax.scatter(
            df_for_plot.loc[df_for_plot['team_name'] == team, "home_away"],
            df_for_plot.loc[df_for_plot['team_name'] == team, "gd"],
            alpha=0.1,
            label=team
            )
    ax.set_xlabel('Location', fontsize=15)
    ax.set_ylabel('Goal difference', fontsize=15)
    ax.legend()
    fig.tight_layout()
    img = BytesIO()
    fig.savefig(img, format="png")
    data = base64.b64encode(img.getbuffer()).decode("ascii")

    return render_template('show_plot.html', plot_url=data, title="Plot GD by Home or Away")

@app.route("/sign_up", methods=('GET', 'POST'))
def sign_up():
    """collects information to create a new user
    Args:
      None
    Returns:
      if GET, renders a form to collect information
      if POST, creates a salted password hash and stores it into users DB table
    """
    if request.method == 'GET':
        return render_template('create_user.html')
    else:
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_check = request.form['password_check']
        salt = sha256(str(time.time()).encode('utf-8')).hexdigest()
        conn = get_db_connection()
        users = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close
        
        if password != password_check:
            flash('password entries do not match')
            return render_template('create_user.html')
        elif users is None:
            # if users is None then the user does not already exist in the data base and can be created
            pw_hash = sha256((salt + password).encode('utf-8')).hexdigest()
            current_cookie = sha256((salt + password + str(time.time())).encode('utf-8')).hexdigest()
            conn = get_db_connection()
            conn.execute("INSERT INTO users (username, email, salt, pw_hash, current_cookie) VALUES (?, ?, ?, ?, ?)",
                (username, email, salt, pw_hash, current_cookie))
            conn.commit()
            conn.close()
            try:
                send_email(username, email, current_cookie)
            except:
                flash('Sorry, please enter a valid email address')
                return render_template('create_user.html')
            flash('new user created please check your email')
            return render_template('index.html')
        elif users["username"] == username:
            flash('Sorry that user already exists. Please choose a different username')
            return render_template('create_user.html')


@app.route("/sign_in", methods=("GET", "POST"))
def sign_in():
    """creates form user login
    Args:
      None
    Returns:
      if GET, renders a form
      if POST, checks the entered password against the stored salted and hashed password_check
        and if the password matches, sets a cookie
    """
    if request.method == 'GET':
        return render_template('sign_in.html')
    else:
        username = request.form['username']
        password = request.form['password']
        target_page = ""
        if 'target_page' in request.form:
            target_page = request.form['target_page']
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if row is None:
            flash('Sorry we do not recognise that user')
            return render_template('sign_in.html')
        username_in_db = row[1]
        pw_hash_in_db = row[3]
        salt = row[4]
        current_cookie = row[5]
        pw_hash = sha256((salt + password).encode('utf-8')).hexdigest()
        if pw_hash_in_db == pw_hash:
            if target_page == "":
                resp = make_response(render_template('index.html'))
                resp.set_cookie('username', username_in_db)
                resp.set_cookie('current_cookie', current_cookie)
                flash('login successful')
                return resp
            else:
                resp = redirect(target_page)
                resp.set_cookie('username', username_in_db)
                resp.set_cookie('current_cookie', current_cookie)
                flash('login successful')
                return resp
        else:
            flash('login failed. Please try again')
            return render_template('sign_in.html')

@app.route("/verify-email", methods=("GET", "POST"))
def verify_email():
    """updates the email verification status in the database
    Args:
      None - but arguments received from request.args in the url
    Returns:
      render template for sign in if the request argument details are valid
      render template for sign up if the request argument details are not valid
    """
    username = request.args.get('user')
    cookie = request.args.get('cookie')
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if row is None:
        flash('Sorry we do not recognise that user')
        return render_template('create_user.html')
    username_in_db = row[1]
    current_cookie = row[5]
    if ((username_in_db == username) and (current_cookie == cookie)):
        conn = get_db_connection()
        curs = conn.cursor()
        curs.execute("UPDATE users SET email_verification = 1 WHERE username = ?", (username,))
        conn.commit()
        flash('Congratulations, your email has been verified')
        return redirect(url_for('sign_in'))
    else:
        flash("Unfortunately, we don't recognise those details - please check your email or create a new account")
        return render_template('create_user.html')

@app.route("/reset_password", methods=("GET", "POST"))
def reset_password():
    """allows user to update stored password in database
    Args:
      None
    Returns:
      if GET, renders a form to get the old and new password details
      if POST, redirects to sign in if the details were valid or back to reset_password if not valid
    """
    if request.method == "GET":
        return render_template("reset_password.html")
    else:
        username = request.form["username"]
        old_password = request.form["old_password"]
        new_password = request.form["new_password"]
        new_password_check = request.form["new_password_check"]
        
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if new_password != new_password_check:
            flash('The new passwords you entered do not match')
            return render_template('reset_password.html')
        if row is None:
            flash('Sorry we do not recognise that user')
            return render_template('reset_password.html')
        
        username_in_db = row[1]
        salt = row[4]
        password_hash_in_db = row[3]
        old_pw_hash = sha256((salt + old_password).encode('utf-8')).hexdigest()
        if old_pw_hash != password_hash_in_db:
            flash('Sorry but your old password was not recognised')
            return render_template('reset_password.html')
        
        new_password_hash = sha256((salt + new_password).encode('utf-8')).hexdigest()
        
        conn = get_db_connection()
        curs = conn.cursor()
        curs.execute("UPDATE users SET pw_hash = ? WHERE username = ?", (new_password_hash, username,))
        conn.commit()
        flash('Congratulations, your your password has been updated')
        return redirect(url_for('sign_in'))

@app.route("/sign_out", methods=("GET", "POST"))
def sign_out():
    """sets cookie values to empty string
    Args:
      None
    Returns:
      response with new cookie values
    """
    resp = make_response(render_template('index.html'))
    resp.set_cookie('username', "")
    resp.set_cookie('current_cookie', "")
    return resp
