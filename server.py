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
    socketio.run(app, host="172.20.10.2", allow_unsafe_werkzeug=True)
