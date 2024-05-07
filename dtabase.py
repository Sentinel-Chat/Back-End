import sqlite3

# Connect to the SQLite database (the database will be created if it doesn't exist)
conn = sqlite3.connect('messaging_app.db')

# Enable foreign key constraint enforcement
conn.execute("PRAGMA foreign_keys = ON;")

# Create tables with foreign key constraints
conn.execute('''
CREATE TABLE IF NOT EXISTS User (
    username CHAR(50) PRIMARY KEY,
    password CHAR(50) NOT NULL
);
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS ChatRoom (
    chat_room_id INTEGER PRIMARY KEY,
    created_at DATE NOT NULL,
    nickname CHAR(50)
);
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS Messages (
    message_id INTEGER PRIMARY KEY,
    sender INTEGER NOT NULL,
    chat_room_id INTEGER NOT NULL,
    created_at DATE NOT NULL,
    text CHAR(250),
    FOREIGN KEY (sender) REFERENCES User (username),
    FOREIGN KEY (chat_room_id) REFERENCES ChatRoom (chat_room_id)
);
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS ChatRoomMembers (
    chat_room_members_id INTEGER PRIMARY KEY,
    username CHAR(50) NOT NULL,
    chat_room_id INTEGER NOT NULL,
    FOREIGN KEY (username) REFERENCES User (username),
    FOREIGN KEY (chat_room_id) REFERENCES ChatRoom (chat_room_id)
);
''')

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Database and tables created with foreign key constraints enforced.")
