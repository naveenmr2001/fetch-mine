import sqlite3

def create_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                  (name TEXT ,gmail TEXT PRIMARY KEY,logo TEXT, password TEXT)''')

    conn.commit()
    conn.close()

# def drop_table():
#     conn = sqlite3.connect('database.db')
#     cursor = conn.cursor()
    
#     cursor.execute('''DROP TABLE users''');
#     conn.commit()
#     conn.close()

# if __name__ == "__main__":
#     drop_table()