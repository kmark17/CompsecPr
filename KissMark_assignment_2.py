
def bytes2binary(byte_input):
    '''
    >>> bytes2binary(b'\\x01')
    '00000001'
    >>> bytes2binary(b'\\x03')
    '00000011'
    >>> bytes2binary(b'\\xf0')
    '11110000'
    >>> bytes2binary(b'\\xf0\\x80')
    '1111000010000000'
    '''

    return ''.join(bin(byte_input[x])[2:].rjust(8, '0') for x in range(len(byte_input)))


# Ref: Week 2 - solutions
def bin2hex(binary):
    '''
    >>> bin2hex('1111')
    'f'
    >>> bin2hex('1')
    '1'
    '''

    ret = hex(int(binary, 2))[2:]
    return ret


def binary2bytes(bin_input):
    '''
    >>> binary2bytes('00000001')
    b'\\x01'
    >>> binary2bytes('00000011')
    b'\\x03'
    >>> binary2bytes('11110000')
    b'\\xf0'
    >>> binary2bytes('1111000010000000')
    b'\\xf0\\x80'
    '''

    bin_input_padded = bin_input.rjust(8, '0')
    bin_chunks = [bin_input_padded[x:x + 8] for x in range(0, len(bin_input_padded), 8)]
    hex_chunks = [int(bin2hex(x), 16) for x in bin_chunks]

    return bytes(hex_chunks)


# Ref: Week 3 - solutions
def bin_xor(bin_input_1, bin_input_2):
    '''
    >>> bin_xor('1011','0000')
    '1011'
    >>> bin_xor('1','0000')
    '0001'
    >>> bin_xor('1101','1011')
    '0110'
    >>> bin_xor('10101010','01010101')
    '11111111'
    '''

    target_len = max(len(bin_input_1), len(bin_input_2))
    bin_input_1_padded = bin_input_1.rjust(target_len, '0')
    bin_input_2_padded = bin_input_2.rjust(target_len, '0')

    bin3 = ""

    for i in range(len(bin_input_1_padded)):
        b1 = bin_input_1_padded[i]
        b2 = bin_input_2_padded[i]

        if b1 == b2:
            bin3 += "0"
        else:
            bin3 += "1"

    return bin3


# Ref: Week 6 - solutions
def bit_permutation(input, permutation_list):
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

    ret = ""
    for p in permutation_list:
        ret += input[p-1]
    return ret


# Ref: Week 6 - solutions
def left_shift_rot(input, repeat=1):
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
    return input[repeat:] + input[:repeat]


key_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19,
       12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37,
       47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34,
       53, 46, 42, 50, 36, 29, 32]


def create_DES_subkeys(K):
    '''
    >>> create_DES_subkeys('0001001100110100010101110111100110011011101111001101111111110001')
    ['000110110000001011101111111111000111000001110010', '011110011010111011011001110110111100100111100101', '010101011111110010001010010000101100111110011001', '011100101010110111010110110110110011010100011101', '011111001110110000000111111010110101001110101000', '011000111010010100111110010100000111101100101111', '111011001000010010110111111101100001100010111100', '111101111000101000111010110000010011101111111011', '111000001101101111101011111011011110011110000001', '101100011111001101000111101110100100011001001111', '001000010101111111010011110111101101001110000110', '011101010111000111110101100101000110011111101001', '100101111100010111010001111110101011101001000001', '010111110100001110110111111100101110011100111010', '101111111001000110001101001111010011111100001010', '110010110011110110001011000011100001011111110101']
    '''

    K_plus = bit_permutation(K, PC1)
    C_zero = K_plus[:28]
    D_zero = K_plus[28:]
    C_n = []
    D_n = []

    for x in range(len(key_shifts)):
        if len(C_n) == 0:
            C_n.append(left_shift_rot(C_zero, key_shifts[x]))
            D_n.append(left_shift_rot(D_zero, key_shifts[x]))
        else:
            C_n.append(left_shift_rot(C_n[x - 1], key_shifts[x]))
            D_n.append(left_shift_rot(D_n[x - 1], key_shifts[x]))

    C_n_D_n = [i + j for i, j in zip(C_n, D_n)]
    K_n = [bit_permutation(x, PC2) for x in C_n_D_n]

    return K_n


E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
     22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

S = \
[
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25]


def f(R0, K1):
    '''
    >>> f('11110000101010101111000010101010', '000110110000001011101111111111000111000001110010')
    '00100011010010101010100110111011'
    '''

    E_R0 = bit_permutation(R0, E)
    K1_plus_E_R0 = bin_xor(E_R0, K1)

    K1_plus_E_R0_6bit_chunks = [K1_plus_E_R0[i:i + 6] for i in range(0, len(K1_plus_E_R0), 6)]
    S_B = []

    for x in range(len(K1_plus_E_R0_6bit_chunks)):
        i = int(K1_plus_E_R0_6bit_chunks[x][0] + K1_plus_E_R0_6bit_chunks[x][-1], 2)
        j = int(K1_plus_E_R0_6bit_chunks[x][1:5], 2)
        S_B.append(bin(S[x][i][j])[2:].rjust(4, '0'))

    f = bit_permutation(''.join(S_B), P)

    return f


IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IP_inverse = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]


def encrypt_DES(K, M):
    '''
    >>> encrypt_DES(b'\\x13\\x34\\x57\\x79\\x9b\\xbc\\xdf\\xf1', b'\\x01\\x23\\x45\\x67\\x89\\xab\\xcd\\xef')
    b'\\x85\\xe8\\x13T\\x0f\\n\\xb4\\x05'
    '''

    K_bin = bytes2binary(K)
    M_bin = bytes2binary(M)
    IP_bin = bit_permutation(M_bin, IP)
    K_n = create_DES_subkeys(K_bin)
    L_n = [IP_bin[:32]]
    R_n = [IP_bin[32:]]

    for x in range(16):
        if x == 0:
            R_n.append(bin_xor(L_n[x], f(R_n[x], K_n[x])))
            L_n.append(R_n[x])
        else:
            L_n.append(R_n[-1])
            R_n.append(bin_xor(L_n[x], f(R_n[x], K_n[x])))

    R16_L16 = R_n[-1] + L_n[-1]
    IP_inverse_bin = bit_permutation(R16_L16, IP_inverse)
    cipher_text = binary2bytes(IP_inverse_bin)

    return cipher_text


from Crypto.Cipher import DES

# Ref.: PyCryptodome - Single DES
#         - https://pycryptodome.readthedocs.io/en/latest/src/cipher/des.html
def encrypt_DES_AES(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    message = cipher.encrypt(plaintext)
    return message


import os


def are_random_tests_all_passes(num_of_tests):
    '''
    >>> are_random_tests_all_passes(100)
    True
    >>> are_random_tests_all_passes(5000)
    True
    >>> are_random_tests_all_passes(20000)
    True
    '''

    test_result = True

    for x in range(num_of_tests):
        M = os.urandom(8)
        K = os.urandom(8)
        message_1 = encrypt_DES_AES(K, M)
        message_2 = encrypt_DES(K, M)

        if message_1 != message_2:
            test_result = False
            break

    return test_result
