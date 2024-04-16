import os
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
socketio = SocketIO(app, cors_allowed_origins="*")

# Dictionary to store session keys for each client
client_session_keys = {}

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

# Handle sent messages from clients
@socketio.on('message')
def handle_message(data):
    print('Received encrypted message:', data)

    # Decrypt the message using the session key
    session_key = client_session_keys[data['sender']]
    cipher = Cipher(algorithms.AES(session_key), modes.CTR(data['iv']), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(data['encrypted_message']) + decryptor.finalize()

    print('Decrypted message:', decrypted_message.decode())

# Handle 'login' messages from the client
@socketio.on('login')
def handle_login(data):
    print('User logged in:', data)
    
    # Generate a session key for the client
    session_key = os.urandom(32)
    client_session_keys[data['username']] = session_key

    # Encrypt the session key with the client's public key
    encrypted_session_key = server_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Send the encrypted session key to the client
    emit('session_key', {'username': data['username'], 'encrypted_session_key': encrypted_session_key})

# Print connect message on successful connection
@socketio.on('connect')
def handle_connection():
    print('New Client Connected')

# Print disconnect message when user disconnects
@socketio.on('disconnect')
def handle_disconnect():
    print('Client Disconnected')

# Replace "YOUR_IP_ADDRESS" with your IP address
if __name__ == '__main__':
    socketio.run(app, host="172.16.5.4")