import sqlite3

# Connect to the SQLite database (the database will be created if it doesn't exist)
conn = sqlite3.connect('messaging_app.db')

# Enable foreign key constraint enforcement
conn.execute("PRAGMA foreign_keys = ON;")

# Create tables with foreign key constraints
conn.execute('''
CREATE TABLE IF NOT EXISTS User (
    user_id INTEGER PRIMARY KEY,
    username CHAR(50) NOT NULL UNIQUE,
    password CHAR(50) NOT NULL,
    profile_pic BLOB
);
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS ChatRoom (
    chat_room_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at DATE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES User (user_id)
);
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS Messages (
    message_id INTEGER PRIMARY KEY,
    sender INTEGER NOT NULL,
    chat_room_id INTEGER NOT NULL,
    created_at DATE NOT NULL,
    text CHAR(250),
    status BOOLEAN NOT NULL,
    FOREIGN KEY (sender) REFERENCES User (user_id),
    FOREIGN KEY (chat_room_id) REFERENCES ChatRoom (chat_room_id)
);
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS Attachments (
    attachment_id INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL,
    data BLOB NOT NULL,
    FOREIGN KEY (message_id) REFERENCES Messages (message_id)
);
''')

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Database and tables created with foreign key constraints enforced.")
