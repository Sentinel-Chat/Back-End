from flask import Flask, request
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
socketio = SocketIO(app, cors_allowed_origins="*")


# Handle sent messages from clients
@socketio.on('message')
def handle_message(message):
    print('Received message: ' + message['text'])  # Access the 'text' property directly
    emit('message', message, broadcast=True)

# @app.route('/api/endpoint', methods=['POST'])
# def handle_data():
#     data = request.json
#     # Process the JSON data as needed
#     print("Received data from frontend:", data)
#     emit('message', data, broadcast=True)
#     return 'Data received successfully'

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
