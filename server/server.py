import socket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1"
PORT = 5555

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))

server.listen()

print(f"[*] Server listening on {HOST}:{PORT}")

client_socket, client_address = server.accept()

print(f"[+] Connection from {client_address}")

# LOAD SERVER PRIVATE KEY
with open("keys/server_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# LOAD SERVER PUBLIC KEY
with open("keys/server_public.pem", "rb") as f:
    public_key_data = f.read()

# SEND PUBLIC KEY TO CLIENT
client_socket.send(public_key_data)

# RECEIVE ENCRYPTED AES SESSION KEY
encrypted_session_key = client_socket.recv(1024)

# DECRYPT SESSION KEY USING RSA PRIVATE KEY
session_key = private_key.decrypt(
    encrypted_session_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("[*] AES session key securely received.")

aes = AESGCM(session_key)

# RECEIVE ENCRYPTED MESSAGE
data = client_socket.recv(1024)

nonce = data[:12]

ciphertext = data[12:]

plaintext = aes.decrypt(
    nonce,
    ciphertext,
    None
)

print("[CLIENT]:", plaintext.decode())

# SEND ENCRYPTED REPLY
reply = "Secure RSA key exchange successful!"

import os

reply_nonce = os.urandom(12)

encrypted_reply = aes.encrypt(
    reply_nonce,
    reply.encode(),
    None
)

client_socket.send(reply_nonce + encrypted_reply)

client_socket.close()

server.close()