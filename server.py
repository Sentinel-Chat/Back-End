from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
socketio = SocketIO(app, cors_allowed_origins ="*")

'''
@socketio.on('message')
def handle_message(message):
    print('Received message: ' + message)
    #emit('message', message, broadcast=True)
'''

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

#replace "IP" with your ip
if __name__ == '__main__':
    socketio.run(app, host="IP")