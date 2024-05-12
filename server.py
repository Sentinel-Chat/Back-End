from flask import Flask, json, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
from datetime import datetime
import sqlite3
from flask_cors import CORS  # Import CORS from flask_cors
from flask import g

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64
import os

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})  # Allow CORS for specific routes
app.config['SECRET_KEY'] = 'secret'
socketio = SocketIO(app, cors_allowed_origins="*")  # Enable CORS for SocketIO

# conn = sqlite3.connect('messaging_app.db')
# conn.execute("PRAGMA foreign_keys = ON;")

# Generate RSA key pair for the server
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
server_public_key = server_private_key.public_key()

# Serialize server's public key
server_public_key_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Dictionary to store session keys for each client (temp solution)
client_session_keys = {}

# Function to get SQLite connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('messaging_app.db')
        db.execute("PRAGMA foreign_keys = ON;")
    return db

# Function to close SQLite connection
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()



@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    print('Account Created for: ' + username) 

    # Insert new user into the User table
    try:
        conn = get_db()
        conn.execute("INSERT INTO User (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except sqlite3.IntegrityError as e:
        return jsonify({'error': 'Username already taken'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/login', methods=['POST'])
def login():
    print('Starting login')
    data = request.json
    username = data.get('username')
    user_public_key = data.get('userPublicKey')  # Ensure the key name matches the client-side key name
    
    user_public_key = load_pem_public_key(user_public_key.encode())
    
    print("printing user public key:")
    # print(user_public_key)  # Print the received public key to verify

    # Query the database to retrieve the user's information based on the username
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM User WHERE username=?", (username,))

    user = cursor.fetchone()

    if user:
        # Generate a session key for the client
        session_key = os.urandom(32)
        print(session_key)
        
        client_session_keys[username] = session_key

        # Encrypt the session key with the client's public key
        # Ensure you have the necessary imports for encryption
        encrypted_session_key = user_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # print(encrypted_session_key);

        # If user exists, return user information
        user_info = {
            'username': user[0],
            'password': user[1],
            'sessionKey': base64.b64encode(encrypted_session_key).decode()
        }
        return jsonify(user_info), 200
    else:
        # If user doesn't exist, return an error message
        return jsonify({'error': 'User not found'}), 404


@socketio.on('message')
def handle_message(data):
    print('Received encrypted message:', data)

    # Decrypt the encrypted data using the session key
    session_key = client_session_keys[data['sender']]
    decryptor = Cipher(algorithms.AES(session_key), modes.CTR(data['iv']), backend=default_backend()).decryptor()
    decrypted_data = decryptor.update(base64.b64decode(data['encryptedData'])) + decryptor.finalize()
    decrypted_data = json.loads(decrypted_data)

    # Decrypt the message using the decrypted message encryption key
    message_decryption_key = session_key.decrypt(decrypted_data['encryptedMessageKey'])
    message_decryptor = Cipher(algorithms.AES(message_decryption_key), modes.CTR(decrypted_data['iv']), backend=default_backend()).decryptor()
    decrypted_message = message_decryptor.update(decrypted_data['encryptedMessage']) + message_decryptor.finalize()

    print('Decrypted message:', decrypted_message.decode())

    # Insert the message into the Messages table
    # try:
    #     conn = get_db()
    #     cursor = conn.cursor()

    #     cursor.execute("INSERT INTO Messages (sender, chat_room_id, created_at, text) VALUES (?, ?, ?, ?)",
    #                    (data['sender'], data['chat_room_id'], datetime.strptime(data['created_at'], '%A, %B %d, %Y at %I:%M %p').date(), decrypted_message.decode()))
    #     conn.commit()
    # except Exception as e:
    #     print("Error inserting message:", str(e))
        
@app.route('/api/create_chatroom', methods=['POST'])
def create_chatroom():
    try:
        print("Creating a new chatroom...")
        # Extract data from the request body
        data = request.json
        print("Received data:", data)
        created_at = data.get('created_at')
        nickname = data.get('nickname')

        if nickname == 'General':
            return redirect(url_for('login'))
        
        # Execute SQL to insert a new chatroom
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO ChatRoom (created_at, nickname) VALUES (?, ?)", (created_at, nickname))
        conn.commit()

        # Close the cursor
        cursor.close()

        # Return a success message
        return jsonify({'message': 'Chatroom created successfully'}), 201
    except Exception as e:
        # Return an error message if an exception occurs
        print("Error:", e)
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/create_chatroom_returnID', methods=['POST'])
def create_chatroom_returnID():
    try:
        print("Creating a new chatroom...")
        # Extract data from the request body
        data = request.json
        print("Received data:", data)
        created_at = data.get('created_at')
        nickname = data.get('nickname')
        
        # Execute SQL to insert a new chatroom
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO ChatRoom (created_at, nickname) VALUES (?, ?)", (created_at, nickname))
        conn.commit()

        # Get the ID of the newly inserted chatroom
        chatroom_id = cursor.lastrowid

        # Close the cursor
        cursor.close()

        # Return the ID of the newly created chatroom
        return jsonify({'chatroom_id': chatroom_id}), 201
    except Exception as e:
        # Return an error message if an exception occurs
        print("Error:", e)
        return jsonify({'error': str(e)}), 500


@app.route('/api/get_chatroomsWithUser', methods=['POST'])
def get_chatroomsWithUser():
    try:
        # Extract username from the request body
        data = request.json
        username = data.get('username')
        
        # Execute SQL to fetch all chat rooms that the user is a part of
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT ChatRoom.chat_room_id, ChatRoom.created_at, ChatRoom.nickname FROM ChatRoom JOIN ChatRoomMembers ON ChatRoom.chat_room_id = ChatRoomMembers.chat_room_id WHERE ChatRoomMembers.username=?", (username,))
        # cursor.execute("SELECT * FROM ChatRoomMembers")
        chatrooms = cursor.fetchall()
        
        # Close the cursor
        cursor.close()
        
        # Return the chat rooms as JSON response
        return jsonify({'chatrooms': chatrooms}), 200
    except Exception as e:
        # Return an error message if an exception occurs
        return jsonify({'error': str(e)}), 500
    
    
@app.route('/api/add_user_to_chatroom', methods=['POST'])
def add_user_to_chatroom():
    try:
        # Extract data from the request body
        data = request.json
        username = data.get('username')
        chat_room_id = data.get('chat_room_id')
        
        # Execute SQL to insert the user into the chat room
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO ChatRoomMembers (username, chat_room_id) VALUES (?, ?)", (username, chat_room_id))
        conn.commit()
        
        # Close the cursor
        cursor.close()
        
        # Return a success message
        return jsonify({'message': 'User added to chatroom successfully'}), 200
    except Exception as e:
        # Return an error message if an exception occurs
        return jsonify({'error': str(e)}), 500

@app.route('/api/get_messages_by_chatroom_id', methods=['POST'])
def get_messages_by_chatroom_id():
    try:
        # Extract chatroom_id from the request body
        data = request.json
        chatroom_id = data.get('chatroom_id')
                
        # Execute SQL to fetch messages by chatroom ID
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Messages WHERE chat_room_id = ?", (chatroom_id,))
        messages = cursor.fetchall()
        
        if messages:
            # Transform each row into a dictionary with specific keys
            formatted_messages = []
            for message in messages:
                formatted_message = {
                    'text': message[4],  # Text of the message
                    'sender': message[1],  # Sender's username
                    'created_at': message[3],  # Timestamp
                    'chat_room_id': message[2]  # Chatroom ID
                }
                formatted_messages.append(formatted_message)

            # Return the formatted messages as JSON response
            return jsonify({'messages': formatted_messages}), 200
        else:
            return jsonify({'messages': []})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    
@app.route('/api/insert_message', methods=['POST'])
def insert_message():
    try:
        # Extract data from the request body
        data = request.json
        text = data.get('text')
        sender = data.get('sender')
        created_at = data.get('created_at')
        chat_room_id = data.get('chat_room_id')  # Assuming chat_room_id is also provided

        created_at = created_at.split(',')
        created_at[1] = created_at[1].split(' ')
        created_at[2] = created_at[2].split(' ')

        year = created_at[2][1]
        month = created_at[1][1]
        day = created_at[1][2]

        date = datetime.date(year, month, day)
        
        # Execute SQL to insert the new message
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Messages (text, sender, created_at, chat_room_id) VALUES (?, ?, ?, ?)",
                       (text, sender, date, chat_room_id))
        conn.commit()

        # Close the cursor
        cursor.close()

        # Return a success message
        return jsonify({'message': 'Message inserted successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# Endpoint to get all usernames from the users table
@app.route('/api/get_all_usernames', methods=['GET'])
def get_all_usernames():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM User")
        usernames = cursor.fetchall()
        cursor.close()
        return jsonify({'usernames': [username[0] for username in usernames]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Handle 'login' messages from the client
@socketio.on('login')
def handle_login(data):
    print('User logged in:', data['username'])
    
# Handle 'login' messages from the client
@socketio.on('logout')
def handle_logout(data):
    print('User logout as:', data['username'])


# Print connect message on succesful connection
@socketio.on('connect')
def handle_connection():
    print('*')


# Print disconnect message when user disconnects
# @socketio.on('disconnect')
# def handle_connection():
#     print('')


# replace "YOUR_IP_ADDRESS" with your ip
if __name__ == '__main__':
    socketio.run(app, host="192.168.254.12", port=5000)
