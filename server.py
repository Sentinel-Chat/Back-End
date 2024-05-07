from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import sqlite3
from flask_cors import CORS  # Import CORS from flask_cors


app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})  # Allow CORS for specific routes
app.config['SECRET_KEY'] = 'secret'
socketio = SocketIO(app, cors_allowed_origins="*")  # Enable CORS for SocketIO

conn = sqlite3.connect('messaging_app.db')
conn.execute("PRAGMA foreign_keys = ON;")


@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    print('Account Created for: ' + username) 

    # Insert new user into the User table
    try:
        conn.execute("INSERT INTO User (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        return jsonify({'error :(': str(e)}), 500
    
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')

    # Query the database to retrieve the user's information based on the username
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM User WHERE username=?", (username,))
    user = cursor.fetchone()

    if user:
        # If user exists, return user information
        user_info = {
            'username': user[0],
            'password': user[1]
        }
        return jsonify(user_info), 200
    else:
        # If user doesn't exist, return an error message
        return jsonify({'error': 'User not found'}), 404


# Handle sent messages from clients
@socketio.on('message')
def handle_message(message):
    print('Received message: ' + message['text'])  # Access the 'text' property directly
    emit('message', message, broadcast=True)
    
    # Insert the message into the Messages table
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Messages (sender, chat_room_id, created_at, text) VALUES (?, ?, ?, ?)",
                       (message['sender'], message['chat_room_id'], message['created_at'], message['text']))
        conn.commit()
    except Exception as e:
        print("Error inserting message:", str(e))
        
@app.route('/api/create_chatroom', methods=['POST'])
def create_chatroom():
    try:
        print("Creating a new chatroom...")
        # Extract data from the request body
        data = request.json
        print("Received data:", data)
        created_at = data.get('created_at')
        nickname = data.get('nickname')
        
        # Execute SQL to insert a new chatroom
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

        print(data)
        
        # Execute SQL to insert the new message
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Messages (text, sender, created_at, chat_room_id) VALUES (?, ?, ?, ?)",
                       (text, sender, created_at, chat_room_id))
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
    socketio.run(app, host="192.168.254.12")
