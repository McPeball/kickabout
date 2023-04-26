import sqlite3

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

def get_users ():
    conn = get_db_connection()
    curs = conn.cursor()
    users = curs.execute("SELECT * FROM users").fetchall()
    conn.close
    for user in users:
        print("\n>>> Next user")
        print("  id: "+str(user['id']))
        print("  username: "+str(user['username']))
        print("  email: "+str(user['email']))
        print("  password hash: "+str(user['pw_hash']))
        print("  password salt: "+str(user['salt']))
        print("  cookie: "+str(user['current_cookie']))
        print("  email verification: "+str(user['email_verification']))

def get_matches ():
    conn = get_db_connection()
    curs = conn.cursor()
    matches = curs.execute("SELECT * FROM matches").fetchall()
    conn.close
    for match in matches:
        for item in match:
            print(item)

#get_matches()

get_users()

