from main import *

# encryption and decryption using EBC MODE
# EBC replaces each block of plain text with encrypted text

class ECB_mode:
    def __init__(self, k):
        self.key = k
    # encryption
    def encrypt(self, plaintext):
        ciphertext = b''
        padding = 16 - len(plaintext) % 16

        # adding padding if necessary, this method adds pad with bytes that have
        # the same value as the number of padding bytes( e.g we need 4 bytes padding
        # at the end of the file we will have 4 bytes of 4 :abc..4444)

        plaintext = plaintext + bytes([padding] * padding)
        while plaintext:
            block = plaintext[0:16]
            plaintext = plaintext[16:]
            enc_block = get_enc_block(block, self.key)  # encryption function
            ciphertext += enc_block
        return ciphertext



    def decrypt(self, ciphertext):
        if len(ciphertext) % 16 != 0:
            print('incorrect ciphertext')
            return
        plaintext = b''
        while ciphertext:
            block = ciphertext[0:16]
            ciphertext = ciphertext[16:]
            dec_block = get_dec_block(block, self.key)  # decryption function
            plaintext += dec_block

        # removing the padding
        count = 0
        current_pad = 0
        for c in plaintext[-16:]:
            if c != current_pad:
                current_pad = c
                count = 1
            else:
                count += 1
        if count != current_pad:
            print('Incorrect padding')
            return
        return plaintext[:-count]