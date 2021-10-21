import os
import socket
import main
from AES_mode import *

K = os.urandom(16)  # K->the key

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((main.HOST, main.KM_PORT))  # connecting to the port
    s.listen()
    conn, _ = s.accept()
    with conn:
        data = conn.recv(3)  # the mode of operation which was sent by node A
        print(f'Requested mode of operation: {data.decode("utf-8")}')
        conn.sendall(bytes(AES_encrypt(K, main.k_prime)))  # sending K encrypted with k_prime
