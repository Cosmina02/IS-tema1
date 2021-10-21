import socket
import main
from ECB_mode import *
from OFB_mode import *
from AES_mode import *

key, encrypted_key = b'', b''


# getting the mode of operation from node A
def get_mode_of_encryption():
    mode = conn.recv(3)
    print(f'Mode of operation: {mode.decode("utf-8")}')
    return mode


# decrypting the key received from A
def decrypt_key():
    global key, encrypted_key
    encrypted_key = conn.recv(16)
    print(f'Key from A:{encrypted_key}')
    key = AES_decrypt(encrypted_key, main.k_prime)
    print(f'Decrypted key: {key}')


# sending the start signal(this means B is ready to receive the crypted message
def send_start_signal():
    conn.sendall(bytes("start", "utf-8"))


# getting the crypted message
def get_message():
    file_size_str = conn.recv(4)
    file_size = int(str(file_size_str, "utf-8"))
    return conn.recv(file_size*2)


# decrypting the message using the mode chosen by node A
def decrypt_message(mode, message):
    if mode == main.ECB:
        ecb = ECB_mode(key)
        normal_message = ecb.decrypt(message)
    else:
        ofb = OFB_mode(main.initialization_vector, key)
        normal_message = ofb.decrypt(message)
    return normal_message


# connection with node A
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((main.HOST, main.A_to_B_PORT))
    s.listen()
    conn, _ = s.accept()
    with conn:
        mode_of_operation = get_mode_of_encryption()
        decrypt_key()
        send_start_signal()
        decrypted_message = decrypt_message(mode_of_operation.decode("utf-8"), get_message())
        print(f'Message from A:{decrypted_message.decode("utf-8")}')

