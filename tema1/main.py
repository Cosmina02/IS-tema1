from AES_mode import *

HOST = '127.0.0.1'
A_to_B_PORT = 6000
KM_PORT = 6100
ECB = 'ECB'
OFB = 'OFB'

k_prime = b'00112233445566778899aabbccddeeff'
initialization_vector = b'0102030405060708'


# XOR function(used by OFB mode)
def get_xor_result_ofb(block, cipher_iv):
    block_xor_cipher_iv = bytes(a ^ b for (a, b) in zip(block, cipher_iv))
    return block_xor_cipher_iv


# encryption function (used by both ECB and OFB)
def get_enc_block(block, key):
    cipherblock = AES_encrypt(block, key)
    return cipherblock


# decryption function (used by ECB mode)
def get_dec_block(block, key):
    plaintext = AES_decrypt(block, key)
    return plaintext
