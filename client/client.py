import socket
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 5555

KEY = b"0123456789abcdef0123456789abcdef"

aes = AESGCM(KEY)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

message = "Hello from client!"

nonce = os.urandom(12)

ciphertext = aes.encrypt(
    nonce,
    message.encode(),
    None
)

client.send(nonce + ciphertext)

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