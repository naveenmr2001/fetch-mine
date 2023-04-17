import sqlite3

def create_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                  (name TEXT ,gmail TEXT PRIMARY KEY,logo TEXT, password TEXT)''')

    conn.commit()
    conn.close()

def create_email_table():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("CREATE TABLE emails(fromemail TEXT, toemail TEXT, subjectemail TEXT,date TEXT);")
    conn.commit()
    conn.close()

def create_footprint_table():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE footprint
                 (name TEXT,
                  url TEXT,
                  logo TEXT,
                  email TEXT)''')
    conn.commit()
    conn.close()

def drop_table():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('''DROP TABLE emails''');
    conn.commit()
    conn.close()

# if __name__ == "__main__":
#     drop_table()