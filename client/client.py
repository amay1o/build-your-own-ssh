import socket

HOST = "127.0.0.1"
PORT = 5555

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

message = "Hello from client!"

client.send(message.encode())

reply = client.recv(1024)

print("[SERVER]:", reply.decode())

client.close()