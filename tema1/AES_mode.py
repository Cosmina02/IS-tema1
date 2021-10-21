from Crypto.Cipher import AES


# AES functions for encrypting and decrypting

def AES_encrypt(message, key):
    aes = AES.new(key, AES.MODE_ECB)
    enc = aes.encrypt(message)
    return enc


def AES_decrypt(ciphertext, key):
    aes = AES.new(key, AES.MODE_ECB)
    dec = aes.decrypt(ciphertext)
    return dec
