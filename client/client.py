import socket
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

HOST = "127.0.0.1"
PORT = 5555

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

# RECEIVE SERVER PUBLIC KEY
public_key_data = client.recv(4096)

public_key = serialization.load_pem_public_key(
    public_key_data
)

print("[*] Server public key received.")

# GENERATE RANDOM AES SESSION KEY
session_key = os.urandom(32)

# ENCRYPT SESSION KEY USING RSA PUBLIC KEY
encrypted_session_key = public_key.encrypt(
    session_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# SEND ENCRYPTED SESSION KEY
client.send(encrypted_session_key)

print("[*] AES session key securely sent.")

aes = AESGCM(session_key)

# ENCRYPT MESSAGE USING AES
message = "Hello from client using RSA key exchange!"

nonce = os.urandom(12)

ciphertext = aes.encrypt(
    nonce,
    message.encode(),
    None
)

client.send(nonce + ciphertext)

# RECEIVE ENCRYPTED REPLY
data = client.recv(1024)

reply_nonce = data[:12]

reply_ciphertext = data[12:]

reply_plaintext = aes.decrypt(
    reply_nonce,
    reply_ciphertext,
    None
)

print("[SERVER]:", reply_plaintext.decode())

client.close()