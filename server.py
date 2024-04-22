from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import sqlite3
from flask_cors import CORS  # Import CORS from flask_cors


app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'secret'
socketio = SocketIO(app, cors_allowed_origins="*")

conn = sqlite3.connect('messaging_app.db')
conn.execute("PRAGMA foreign_keys = ON;")


@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    print('Received message: ' + username + password)  # Access the 'text' property directly

    # Insert new user into the User table
    try:
        conn.execute("INSERT INTO User (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        return jsonify({'error :(': str(e)}), 500


# Handle sent messages from clients
@socketio.on('message')
def handle_message(message):
    print('Received message: ' + message['text'])  # Access the 'text' property directly
    emit('message', message, broadcast=True)

# Handle 'login' messages from the client
@socketio.on('login')
def handle_login(data):
    print('User logged in:', data)


# Print connect message on succesful connection
@socketio.on('connect')
def handle_connection():
    print('New Client Connected')


# Print disconnect message when user disconnects
@socketio.on('disconnect')
def handle_connection():
    print('Client Disconnected')


# replace "YOUR_IP_ADDRESS" with your ip
if __name__ == '__main__':
    socketio.run(app, host="192.168.254.12", allow_unsafe_werkzeug=True)
