# Task 1
# We have a one-byte key and we encrypt all of the bytes of the plain text by adding the key
# for every byte and modulo by 256. # If you encrypt a text with a key then the decryption
# key will be 256-key (e.g. Encryption key 123, Decryption key: 133)

# Task 2
# We have a one byte sized key, xor the first byte of the plaintext and that will be the cipher for the first byte.
# To encrypt the second byte use the cipher of the message first byte as key and so on. Implement the function that
# can do encryption and decryption as well based on the third argument (as you can see in the doctest).

# Task 3
# Create a new scheme, that uses the previous scheme as a sub step. The  encryption algorithm working with
# 4 byte length keys. Run for the 1,5,9...th bytes the previous encryption with the first byte of the key.
# Run for the 2,6,10...th bytes the previous encryption with the second byte of the key. etc. similarly for the 4 bytes
# of the key.
# That means this algorithms splits up the input to 4 new inputs and feeds those 8 inputs for the previous scheme that
# uses only one byte length key.


# Ref: Week 3 - solutions
def string2hex(message):
    '''
    >>> string2hex('a')
    '61'
    >>> string2hex('hello')
    '68656c6c6f'
    >>> string2hex('world')
    '776f726c64'
    >>> string2hex('foo')
    '666f6f'
    '''

    ret = ""
    for c in message:
        ret += hex(ord(c))[2:].rjust(2, '0')

    return ret


# Ref: Week 3 - solutions
def hex2string(hex_message):
    '''
    >>> hex2string('61')
    'a'
    >>> hex2string('776f726c64')
    'world'
    >>> hex2string('68656c6c6f')
    'hello'
    '''

    ret = ""
    for i in range(0, len(hex_message), 2):
        ret += chr(int(hex_message[i:i + 2], 16))

    return ret


# Ref: Week 2 - solutions
def hex_xor(hex1, hex2):
    '''
    >>> hex_xor('aabbf11','12345678')
    '189fe969'
    >>> hex_xor('12cc','12cc')
    '0000'
    >>> hex_xor('1234','2345')
    '3171'
    >>> hex_xor('111','248')
    '359'
    >>> hex_xor('8888888','1234567')
    '9abcdef'
    '''

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


# Task 1

def encrypt_by_add_mod(plain_text, key):
    '''
    >>> encrypt_by_add_mod('Hello',123)
    'Ãàççê'
    >>> encrypt_by_add_mod(encrypt_by_add_mod('Hello', 123), 133)
    'Hello'
    >>> encrypt_by_add_mod(encrypt_by_add_mod('Cryptography', 10), 246)
    'Cryptography'
    '''

    encrypted_message = [int(string2hex(plain_text[i]), 16) + key for i in range(len(plain_text))]
    ret = [hex2string(hex(encrypted_message[i] % 256)[2:]) if encrypted_message[i] > 256
           else hex2string(hex(encrypted_message[i])[2:]) for i in range(len(encrypted_message))]

    return ''.join(ret)


# Task2

def encrypt_xor_with_changing_key_by_prev_cipher(plain_text, key, encrypt_or_decrypt):
    '''
    >>> encrypt_xor_with_changing_key_by_prev_cipher('Hello',123,'encrypt')
    '3V:V9'
    >>> encrypt_xor_with_changing_key_by_prev_cipher(encrypt_xor_with_changing_key_by_prev_cipher('Hello',123,'encrypt'), 123, 'decrypt')
    'Hello'
    >>> encrypt_xor_with_changing_key_by_prev_cipher(encrypt_xor_with_changing_key_by_prev_cipher('Cryptography',10,'encrypt'), 10, 'decrypt')
    'Cryptography'
    '''

    key_hex = hex(key)[2:]
    plain_text_hex = string2hex(plain_text)
    plain_text_hex_chunks = [plain_text_hex[i:i + 2] for i in range(0, len(plain_text_hex), 2)]
    encrypted_message = []
    changing_key = key_hex
    for chunk in plain_text_hex_chunks:
        encrypted_message.append(hex_xor(chunk, changing_key))
        if encrypt_or_decrypt == "encrypt":
            changing_key = encrypted_message[-1]
        else:
            changing_key = hex_xor(encrypted_message[-1], changing_key)

    return hex2string(''.join(encrypted_message))


# Task 3

def encrypt_xor_with_changing_key_by_prev_cipher_longer_key(plain_text, key_list, encrypt_or_decrypt):
    '''
    >>> key_list = [0x20, 0x44, 0x54,0x20]
    >>> encrypt_xor_with_changing_key_by_prev_cipher_longer_key('abcdefg', key_list, 'encrypt')
    'A&7D$@P'
    >>> encrypt_xor_with_changing_key_by_prev_cipher_longer_key('aaabbbb', key_list, 'encrypt')
    'A%5B#GW'
    >>> encrypt_xor_with_changing_key_by_prev_cipher_longer_key(
    ...    encrypt_xor_with_changing_key_by_prev_cipher_longer_key('abcdefg',key_list,'encrypt'),
    ...        key_list,'decrypt')
    'abcdefg'
    >>> encrypt_xor_with_changing_key_by_prev_cipher_longer_key(
    ...    encrypt_xor_with_changing_key_by_prev_cipher_longer_key('Hellobello, it will work for a long message as well',key_list,'encrypt'),
    ...        key_list,'decrypt')
    'Hellobello, it will work for a long message as well'
    '''

    first_chunk = [plain_text[x] for x in range(0, len(plain_text), 4)]
    second_chunk = [plain_text[x] for x in range(1, len(plain_text), 4)]
    third_chunk = [plain_text[x] for x in range(2, len(plain_text), 4)]
    fourth_chunk = [plain_text[x] for x in range(3, len(plain_text), 4)]

    first_chunk_encrypted = encrypt_xor_with_changing_key_by_prev_cipher(''.join(first_chunk), key_list[0], encrypt_or_decrypt)
    second_chunk_encrypted = encrypt_xor_with_changing_key_by_prev_cipher(''.join(second_chunk), key_list[1], encrypt_or_decrypt)
    third_chunk_encrypted = encrypt_xor_with_changing_key_by_prev_cipher(''.join(third_chunk), key_list[2], encrypt_or_decrypt)
    fourth_chunk_encrypted = encrypt_xor_with_changing_key_by_prev_cipher(''.join(fourth_chunk), key_list[3], encrypt_or_decrypt)

    chunks_joined = []
    ind_first = 0
    ind_second = 0
    ind_third = 0
    ind_fourth = 0
    for x in range(len(first_chunk_encrypted) + len(second_chunk_encrypted)
                + len(third_chunk_encrypted) + len(fourth_chunk_encrypted)):
        if x % 4 == 0 and not ind_first >= len(first_chunk_encrypted):
            chunks_joined.append(first_chunk_encrypted[ind_first])
            ind_first += 1
        elif x % 4 == 1 and not ind_second >= len(second_chunk_encrypted):
            chunks_joined.append(second_chunk_encrypted[ind_second])
            ind_second += 1
        elif x % 4 == 2 and not ind_third >= len(third_chunk_encrypted):
            chunks_joined.append(third_chunk_encrypted[ind_third])
            ind_third += 1
        elif x % 4 == 3 and not ind_fourth >= len(fourth_chunk_encrypted):
            chunks_joined.append(fourth_chunk_encrypted[ind_fourth])
            ind_fourth += 1

    return ''.join(chunks_joined)

