# Create a hex2base64 function that converts, a string containing hex code,
# to base64 encoding without using any library.

base64_table_char = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
                     'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
                     'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                     'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
                     'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6',
                     '7', '8', '9', '+', '/']

base64_table_bin = ['000000', '000001', '000010', '000011', '000100',
                '000101', '000110', '000111', '001000', '001001', '001010',
                '001011', '001100', '001101', '001110', '001111', '010000',
                '010001', '010010', '010011', '010100', '010101', '010110',
                '010111', '011000', '011001', '011010', '011011', '011100',
                '011101', '011110', '011111', '100000', '100001', '100010',
                '100011', '100100', '100101', '100110', '100111', '101000',
                '101001', '101010', '101011', '101100', '101101', '101110',
                '101111', '110000', '110001', '110010', '110011', '110100',
                '110101', '110110', '110111', '111000', '111001', '111010',
                '111011', '111100', '111101', '111110', '111111']


def hex2base64(input_hex):

    '''
    >>> hex2base64('3D')
    'PQ=='
    >>> hex2base64('125413512563462147624513141233122abcde213144')
    'ElQTUSVjRiFHYkUTFBIzEiq83iExRA=='
    >>> hex2base64('123453652322341235abdc')
    'EjRTZSMiNBI1q9w='
    >>> hex2base64('11111abc')
    'EREavA=='
    '''

    # Input to bin. Filling up to 8 length.
    hex2bin = bin(int(input_hex, 16))[2:]
    hex2bin_len_mpy_of_8 = len(hex2bin)
    while hex2bin_len_mpy_of_8 % 8 != 0:
        hex2bin_len_mpy_of_8 += 1
    hex2bin = hex2bin.rjust(hex2bin_len_mpy_of_8, '0')

    # Padding the length of the binary string to multiply of 6.
    hex2bin_len_mpy_of_6 = len(hex2bin)
    while hex2bin_len_mpy_of_6 % 6 != 0:
        hex2bin_len_mpy_of_6 += 1
    hex2bin_padded = hex2bin.ljust(hex2bin_len_mpy_of_6, '0')

    # Slicing the binary string to create 6 length binary strings. Finding the proper matches in the base64 table.
    hex2bin_padded_sliced = [hex2bin_padded[x:x + 6] for x in range(0, len(hex2bin_padded), 6)]
    hex2bin2base64_list = []
    for i in range(len(hex2bin_padded_sliced)):
        index_of_base64_char = base64_table_bin.index(hex2bin_padded_sliced[i])
        hex2bin2base64_list.append(base64_table_char[index_of_base64_char])
    hex2bin2base64 = ''.join(hex2bin2base64_list)

    # Adding the '=' sign.
    base64_len_mpy_of_4 = len(hex2bin2base64)
    while base64_len_mpy_of_4 % 4 != 0:
        base64_len_mpy_of_4 += 1
    return hex2bin2base64.ljust(base64_len_mpy_of_4, '=')



