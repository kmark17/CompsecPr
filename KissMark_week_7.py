
# AES
# Create a function that decrypts a message with AES CBC mode with the given IV and key.
# Here you must use an external AES library that implements the encprytion scheme.

from Crypto.Cipher import AES

# Ref: PyCryptodome: Classic modes of operation for symmetric block ciphers
#       - https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode

def decrypt_aes(plaintext_bytes, key, iv):
    '''
    >>> key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
    >>> iv = bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204])
    >>> decrypt_aes(bytes([255, 18, 67, 115, 172, 117, 242, 233, 246, 69, 81, 156, 52, 154, 123, 171]),key,iv)
    b'hello world 1234'
    >>> decrypt_aes(bytes([171, 218, 160, 96, 193, 134, 73, 81, 221, 149, 19, 180, 31, 247, 106, 64]),key,iv)
    b'lovecryptography'
    '''

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(plaintext_bytes)


def bit_permutation(bin_text, permutation_ind):
    '''
    >>> bit_permutation("101",[1,2,3])
    '101'
    >>> bit_permutation("101",[3,2,1])
    '101'
    >>> bit_permutation("101",[1,3,2])
    '110'
    >>> bit_permutation("101",[3,2,1])
    '101'
    >>> bit_permutation("1010",[3,4,1,2])
    '1010'
    >>> bit_permutation("1010",[1,3,2,4])
    '1100'
    >>> bit_permutation("11110000",[5,6,7,8,1,2,3,4])
    '00001111'
    >>> bit_permutation("0001001100110100010101110111100110011011101111001101111111110001",[57,49, 41,33, 25, 17, 9,1,58, 50,42, 34, 26,18,10, 2, 59,51, 43, 35,27,19,11,  3,60, 52, 44,36,63,55, 47,39, 31, 23,15,7,62, 54,46, 38, 30,22,14, 6, 61,53, 45, 37,29,21,13,  5,28, 20, 12, 4])
    '11110000110011001010101011110101010101100110011110001111'
    '''

    bin_text_list = [x for x in bin_text]

    bin_text_after_permutation = [0 for _ in range(len(permutation_ind))]
    i = 0
    for x in range(len(permutation_ind)):
        bin_text_after_permutation[i] = bin_text_list[permutation_ind[x] - 1]
        i += 1

    return ''.join(bin_text_after_permutation)


def left_shift_rot(bin_text, start_ind = 1):
    '''
    >>> left_shift_rot('010')
    '100'
    >>> left_shift_rot('111')
    '111'
    >>> left_shift_rot('1010111001')
    '0101110011'
    >>> left_shift_rot('0101110011')
    '1011100110'
    >>> left_shift_rot('1010111001',2)
    '1011100110'
    >>> left_shift_rot('0001',3)
    '1000'
    '''

    return ''.join([bin_text[x] if x < len(bin_text) else bin_text[x - len(bin_text)] for x in range(start_ind, len(bin_text) + start_ind, 1)])


def PKCS7_pad():
    '''
     >>> PKCS7_pad('hello',6)
    'hello\\x01'
    >>> PKCS7_pad('hello',7)
    'hello\\x02\\x02'
    >>> PKCS7_pad('hello, how are you?',26)
    'hello, how are you?\\x07\\x07\\x07\\x07\\x07\\x07\\x07'
    >>> PKCS7_pad('hello, how are you?',55)
    'hello, how are you?$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
    >>> PKCS7_pad('hello, how are you?',67)
    'hello, how are you?000000000000000000000000000000000000000000000000'
    '''

