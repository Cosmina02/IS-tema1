from main import *

# encryption and decryption using OFB MODE
# the encryption algorithm is applied to the initialization vector,
# the result being then subjected to an XOR with the next block of
# plaintext, obtaining the encrypted block.


class OFB_mode:
    def __init__(self, iv, k):
        self.initialization_vector = iv
        self.key = k

    def encrypt(self, plaintext):
        ciphertext = b''
        padding = 16 - len(plaintext) % 16

        # adding padding if necessary, this method adds pad with bytes that have
        # the same value as the number of padding bytes( e.g we need 4 bytes padding
        # at the end of the file we will have 4 bytes of 4 :abc..4444)

        plaintext = plaintext + bytes([padding] * padding)
        iv = self.initialization_vector
        while plaintext:
            block = plaintext[0:16]
            plaintext = plaintext[16:]
            iv = get_enc_block(iv, self.key)  # encrypting the initialization vector with the given key
            enc_block = get_xor_result_ofb(block, iv)  # making xor operation between the encrypted iv and the block
            ciphertext += enc_block
        return ciphertext

    def decrypt(self, ciphertext):
        if len(ciphertext) % 16 != 0:
            print('incorrect ciphertext')
            return
        plaintext = b''
        iv = self.initialization_vector
        while ciphertext:
            block = ciphertext[0:16]
            ciphertext = ciphertext[16:]
            iv = get_enc_block(iv, self.key)  # encrypting the initialization vector with the given key
            dec_block = get_xor_result_ofb(block, iv)  # making xor operation between the encrypted iv and the block
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
