import socket
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 5555

KEY = b"0123456789abcdef0123456789abcdef"

aes = AESGCM(KEY)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))

server.listen()

print(f"[*] Server listening on {HOST}:{PORT}")

client_socket, client_address = server.accept()

print(f"[+] Connection from {client_address}")

data = client_socket.recv(1024)

nonce = data[:12]

ciphertext = data[12:]

plaintext = aes.decrypt(nonce, ciphertext, None)

print("[CLIENT]:", plaintext.decode())

reply = "Encrypted hello from server!"

reply_nonce = os.urandom(12)

encrypted_reply = aes.encrypt(
    reply_nonce,
    reply.encode(),
    None
)

client_socket.send(reply_nonce + encrypted_reply)

client_socket.close()

server.close()