
# decrypt_aes_ecb
# Last week we used the AES library in CBC mode. Now create a function that uses the same
# library and decrypt a message that is coded in ECB mode.

from Crypto.Cipher import AES

# Ref: PyCryptodome: Classic modes of operation for symmetric block ciphers
#       - https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode

def decrypt_aes_ecb(plaintext_bytes, key):
    '''
    >>> key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
    >>> decrypt_aes_ecb(bytes([215, 221, 59, 138, 96, 94, 155, 69, 52, 90, 212, 108, 49, 65, 138, 179]),key)
    b'lovecryptography'
    >>> decrypt_aes_ecb(bytes([147, 140, 44, 177, 97, 209, 42, 239, 152, 124, 241, 175, 202, 164, 183, 18]),key)
    b'!!really  love!!'
    '''

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(plaintext_bytes)


# Ref: Week 2 - solutions
def hex_xor(hex1, hex2):

    #Find the bigger length of the two hex
    target_len = max(len(hex1), len(hex2))

    # Pad both of the input to have the same number of zeroes in binary format
    # rjust because: 123 = 0123, but 123 not equal 1230 in decimal case as well
    bin1 = bin(int(hex1, 16))[2:].rjust(target_len*4, '0')
    bin2 = bin(int(hex2, 16))[2:].rjust(target_len*4, '0')

    bin3 = ""

    for i in range(len(bin1)):
        b1 = bin1[i]
        b2 = bin2[i]

        if b1 == b2:
            bin3 += "0"
        else:
            bin3 += "1"

    return hex(int(bin3, 2))[2:].rjust(target_len, '0')


# xor_byte_arrays
# Create a function that xors two byte array.  Not that you can use rjust on byte strings arrays as well, like
# input1_padded = input1.rjust(max_len,bytes([0]))

def xor_byte_arrays(plaintext_bytes_1, plaintext_bytes_2):
    '''
    >>> xor_byte_arrays(bytes([1,2,3,4]),bytes([2,3,4,5]))
    b'\\x03\\x01\\x07\\x01'
    >>> xor_byte_arrays(bytes([1,2,3,4]),bytes([]))
    b'\\x01\\x02\\x03\\x04'
    >>> xor_byte_arrays(bytes([1,2,3,4]),bytes([1,2]))
    b'\\x01\\x02\\x02\\x06'
    >>> xor_byte_arrays(bytes([1,2,4,8,16,32,64,128]),bytes([1,1,1,1,1,1,1,1]))
    b'\\x00\\x03\\x05\\t\\x11!A\\x81'
    '''

    ret = []
    target_len = max(len(plaintext_bytes_1), len(plaintext_bytes_2))
    for x in range(target_len):
        if len(plaintext_bytes_1) == 0:
            hex1 = hex(0)[2:]
        elif len(plaintext_bytes_1) == x:
            hex1 = hex(plaintext_bytes_1[len(plaintext_bytes_1) - 1])[2:]
        if len(plaintext_bytes_2) == 0:
            hex2 = hex(0)[2:]
        elif len(plaintext_bytes_2) == x:
            hex2 = hex(plaintext_bytes_2[len(plaintext_bytes_2) - 1])[2:]

        hex1 = hex(plaintext_bytes_1[x])[2:]
        hex2 = hex(plaintext_bytes_2[x])[2:]
        ret.append(int(hex_xor(hex1, hex2), 16))

    return bytes(ret)


# decrypt_aes_cbc_with_ecb
# Implement AES in CBC mode with the previous function. This function must produce the same result as the last week
# function (so the test cases are same). ECB mode is the core of the encryption without any chaining. In CBC mode you
# have some extra xoring: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

# Every encryption CBC encryption method can be built from the implementation of the ECB mode.

def decrypt_aes_cbc_with_ecb(plaintext_bytes, key, iv):
    '''
    >>> key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
    >>> iv = bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204])
    >>> decrypt_aes_cbc_with_ecb(bytes([255, 18, 67, 115, 172, 117, 242, 233, 246, 69, 81, 156, 52, 154, 123, 171]),key,iv)
    b'hello world 1234'
    >>> decrypt_aes_cbc_with_ecb(bytes([171, 218, 160, 96, 193, 134, 73, 81, 221, 149, 19, 180, 31, 247, 106, 64]),key,iv)
    b'lovecryptography'
    '''

    return True