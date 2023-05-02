# Helping functions:

# Ref: Canvas - "Week 3 - solutions"
#       - https://canvas.elte.hu/courses/21877/pages/week-3-solutions
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


# Ref: Canvas - "Week 3 - solutions"
#       - https://canvas.elte.hu/courses/21877/pages/week-3-solutions
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


# Ref: Canvas - "Week 2 - solutions"
#       - https://canvas.elte.hu/courses/21877/pages/week-2-solutions
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


# Tasks:

def key_hex_plain_text_hex_plain_text_hex_chunks(plain_text, key):

    # We work with 1 byte keys. To avoid problems, I embedded a condition for the key being more than 255. If it
    # was the case, I simply modulo it, to still get a 1 byte key.
    if key > 255:
        key_hex = hex(key % 256)[2:].rjust(2, '0')
    else:
        key_hex = hex(key)[2:].rjust(2, '0')

    # The plain text has to be converted to hex, to then later encrypt it.
    plain_text_hex = string2hex(plain_text)

    # Separating the hex plain text to 2 character chunks, as we work with bytes, and data is stored on 8 bits.
    plain_text_hex_chunks = [plain_text_hex[i:i + 2] for i in range(0, len(plain_text_hex), 2)]

    return key_hex, plain_text_hex, plain_text_hex_chunks


def key_for_encrypt_with_power(key):

    # This function is responsible for creating the new key for the encrypt_with_power() function. As I already
    # explained in that function, the key has to be powered to 2, and if the key (in decimal format) is bigger than
    # 255, I have to modulo it, to get a 1 byte key. Otherwise, I simply return the powered key.
    key = int(key, 16) ** 2
    if key > 255:
        return hex(key % 256)[2:]
    else:
        return hex(key)[2:]


# Task 1
# We have one byte sized key and encrypt the first byte of the plain message with the key.
# Power the key byte to 2 and modulo by 256. (e.g. if the key is 3 then the second byte will encrypted by 9,
# and the third by 27 and so on 81, 243, 217...)
# Xor the second byte with this new key byte. Repeat it for the remaining bytes.
def encrypt_with_power(plain_text, key):
    '''
    >>> encrypt_with_power('Hello',250)
    '²A|lo'
    >>> string2hex(encrypt_with_power('Hello',250))
    'b2417c6c6f'
    >>> string2hex(encrypt_with_power(hex2string('acc5522cca'),250))
    '56e1422cca'
    >>> string2hex(encrypt_with_power(hex2string('acc5522cca'),123))
    'd7dc23cd0b'
    >>> string2hex(encrypt_with_power('I love Cryptography!!!',23))
    '5e314d2ef7642142737871756e667360716978202020'
    >>> encrypt_with_power('I love Cryptography!!!',0)
    'I love Cryptography!!!'
    >>> encrypt_with_power('With key 0, it will not be changed!!!',0)
    'With key 0, it will not be changed!!!'
    >>> encrypt_with_power(encrypt_with_power('Hello',123),123)
    'Hello'
    >>> encrypt_with_power(encrypt_with_power('Cryptography',10),10)
    'Cryptography'
    '''

    # To avoid as much redundancy as possible.
    new_key, plain_text_hex, plain_text_hex_chunks = key_hex_plain_text_hex_plain_text_hex_chunks(plain_text, key)

    encrypted_message = []
    for x in range(len(plain_text_hex_chunks)):

        # Encrypting the first plain text's byte with the given key.
        if x == 0:
            encrypted_message.append(hex_xor(plain_text_hex_chunks[x], new_key))

        # In every other scenario, the key for encryption will change (according to the task requirements,
        # in this case, I power the key byte to 2, then modulo it if needed.
        else:
            new_key = key_for_encrypt_with_power(new_key)
            encrypted_message.append(hex_xor(plain_text_hex_chunks[x], new_key))

    # At the end, I simply join the encrypted message list and convert the hexadecimal message to string.
    return hex2string(''.join(encrypted_message))


def key_for_encrypt_with_power2_and_task4(key, plain_text_hex_chunks, encrypted_or_decrypted_message,
                                          ind, encrypt_or_decrypt):

    # Literally the same logic as in the key_for_encrypt_with_power() function. Only difference is that if the key
    # is either 0 or 1, the value of the next or new key is going to be a bit more complicated. If the
    # 'encrypt_or_decrypt' variable is 'encrypt', the plain text's hex chunk's last element will be returned, otherwise
    # (in the case of decryption), the 'encrypted_or_decrypted_message''s last element will be returned. Reason is that
    # when decrypting, I have to reverse the process back, and the last element of the decrypted message will be the
    # equivalent of the plain text's hex chunk's last element.
    key = int(key, 16) ** 2
    if key > 255:
        key = key % 256
    if key == 0 or key == 1:
        if encrypt_or_decrypt == 'encrypt':
            return plain_text_hex_chunks[ind - 1]
        else:
            return encrypted_or_decrypted_message[ind - 1]
    else:
        return hex(key)[2:]


# Task 2
# Extend the previous scheme with the following: when the key would be 0 or 1 then use the previous plain message byte
# as a key for encryption. Hint: in decryption algorithm you get the cipher as input, but to reverse the algorithm you
# have to use the decrypted value.
def encrypt_with_power2(plain_text, key, encrypt_or_decrypt):
    '''
    >>> encrypt_with_power2('Hello',253,'encrypt')
    'µl=Í.'
    >>> encrypt_with_power2('Hello2',131,'encrypt')
    'Ël=Í.³'
    >>> string2hex(encrypt_with_power2('Hello',250,'encrypt'))
    'b2417c00ff'
    >>> string2hex(encrypt_with_power2(hex2string('acc5522cca'),250,'encrypt'))
    '56e1427e8e'
    >>> string2hex(encrypt_with_power2(hex2string('acc5522cca'),123,'encrypt'))
    'd7dc23cd0b'
    >>> string2hex(encrypt_with_power2('I love Cryptography!!!',23,'encrypt'))
    '5e314d2ef713445331f021d52ee6151091a9f8581040'
    >>> encrypt_with_power2('I am',0,'encrypt')
    'Ii°Ì'
    >>> encrypt_with_power2(encrypt_with_power2('Hello',123,'encrypt'),123,'decrypt')
    'Hello'
    >>> encrypt_with_power2(encrypt_with_power2('Hello',234,'encrypt'),234,'decrypt')
    'Hello'
    >>> encrypt_with_power2(encrypt_with_power2('Hello',2,'encrypt'),2,'decrypt')
    'Hello'
    >>> encrypt_with_power2(encrypt_with_power2('Hello',2,'encrypt'),62,'decrypt')
    'tello'
    >>> encrypt_with_power2(encrypt_with_power2('Cryptography',10,'encrypt'),10,'decrypt')
    'Cryptography'
    '''

    # To avoid as much redundancy as possible.
    new_key, plain_text_hex, plain_text_hex_chunks = key_hex_plain_text_hex_plain_text_hex_chunks(plain_text, key)

    encrypted_or_decrypted_message = []
    for x in range(len(plain_text_hex_chunks)):

        # The first chunk has to be encrypted with the given key with tha value that was passed onto the function's
        # parameter.
        if x == 0:
            encrypted_or_decrypted_message.append(hex_xor(plain_text_hex_chunks[x], new_key))
            continue

        # Checking whether I have to use encryption or decryption, based on the given value from 'encrypt_or_decrypt'.
        # Encryption and decryption is the same, only difference is the key, which is explained in the
        # key_for_encrypt_with_power2_and_task4() function, how I get it.
        if encrypt_or_decrypt == 'encrypt':
            new_key = key_for_encrypt_with_power2_and_task4(new_key, plain_text_hex_chunks,
                                                            encrypted_or_decrypted_message, x, encrypt_or_decrypt)
            encrypted_or_decrypted_message.append(hex_xor(plain_text_hex_chunks[x], new_key))
        else:
            new_key = key_for_encrypt_with_power2_and_task4(new_key, plain_text_hex_chunks,
                                                            encrypted_or_decrypted_message, x, encrypt_or_decrypt)
            encrypted_or_decrypted_message.append(hex_xor(plain_text_hex_chunks[x], new_key))

    # At the end, I simply join the hex chunks and convert it to string.
    return hex2string(''.join(encrypted_or_decrypted_message))


# Task 3
# Create a function that flips every second bit in a byte given as integer.
def swap_every_second_bit(_input):
    '''
    >>> swap_every_second_bit(1)
    2
    >>> swap_every_second_bit(2)
    1
    >>> swap_every_second_bit(4)
    8
    >>> swap_every_second_bit(16)
    32
    >>> bin(swap_every_second_bit(0b1010))
    '0b101'
    >>> bin(swap_every_second_bit(0b01010110))
    '0b10101001'
    '''

    # As the key was given in decimal system, first I convert it to hex, cut
    # the '0x' characters and use rjust() function, as we are working with 1 byte key.
    bin_input = bin(_input)[2:]

    # Padding the binary string to 8 length with rjust() function, as we are working with bytes.
    bin_input_padded = bin_input.rjust(8, '0')

    # First I create a list from the binary string's characters to handle them more easily.
    byte_swapped_every_second_bit = [x for x in bin_input_padded]

    # Then I simply utilize python's multiple variable assignment syntax, and I switch up every 2 bits with
    # one another.
    for i in range(0, len(byte_swapped_every_second_bit) - 1, 2):
        byte_swapped_every_second_bit[i], byte_swapped_every_second_bit[i + 1] =\
            byte_swapped_every_second_bit[i + 1], byte_swapped_every_second_bit[i]

    # At the end, I simply join the list to get the binary string, and return it in decimal format, as the
    # task requires it.
    return int(''.join(byte_swapped_every_second_bit), 2)


# Task 4
# Extend the scheme with the following: flip every second bit in every byte before the xor operation.
# For decryption you have to flip after the xor operation to get a symmetric encryption.
def encrypt_with_power_and_swap_every_second_bit(plain_text, key, encrypt_or_decrypt):
    '''
    >>> encrypt_with_power_and_swap_every_second_bit('Hello',120,'encrypt')
    'üÚùEn'
    >>> encrypt_with_power_and_swap_every_second_bit('Hello',200,'encrypt')
    'LÚùEn'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit('Hello',250,'encrypt'))
    '7ebe8cf00f'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit(hex2string('acc5522cca'),250,'encrypt'))
    'a6eeb14e81'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit(hex2string('acc5522cca'),123,'encrypt'))
    '27d3d0fd04'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit('I love Cryptography!!!',23,'encrypt'))
    '9101bdde38ec7493f23fe119de1ad6e35155376b2373'
    >>> encrypt_with_power_and_swap_every_second_bit(encrypt_with_power_and_swap_every_second_bit('Hello',123,'encrypt'),123,'decrypt')
    'Hello'
    >>> encrypt_with_power_and_swap_every_second_bit(encrypt_with_power_and_swap_every_second_bit('Hello',234,'encrypt'),234,'decrypt')
    'Hello'
    >>> encrypt_with_power_and_swap_every_second_bit(encrypt_with_power_and_swap_every_second_bit('Hello',2,'encrypt'),2,'decrypt')
    'Hello'
    >>> encrypt_with_power_and_swap_every_second_bit(encrypt_with_power_and_swap_every_second_bit('Hello',2,'encrypt'),62,'decrypt')
    'tello'
    >>> encrypt_with_power_and_swap_every_second_bit(encrypt_with_power_and_swap_every_second_bit('Cryptography',10,'encrypt'),10,'decrypt')
    'Cryptography'
    '''

    # To avoid as much redundancy as possible.
    new_key, plain_text_hex, plain_text_hex_chunks = key_hex_plain_text_hex_plain_text_hex_chunks(plain_text, key)

    plain_text_hex_chunks_bits_swapped = []
    encrypted_or_decrypted_message = []
    for x in range(len(plain_text_hex_chunks)):

        # The first chunk has to be encrypted with the given key with tha value that was passed onto the function's
        # parameter.
        if x == 0:
            if encrypt_or_decrypt == 'encrypt':

                # Flipping every 2 bits of the chunks, as the task requires.
                for chunk in plain_text_hex_chunks:
                    plain_text_hex_chunks_bits_swapped.append(hex(swap_every_second_bit(int(chunk, 16)))[2:])

                encrypted_or_decrypted_message.append(hex_xor(plain_text_hex_chunks_bits_swapped[x], new_key))
            else:
                # Flipping the bits after the xor operation, for decryption only.
                bits_swapped = hex(swap_every_second_bit(int(hex_xor(plain_text_hex_chunks[x], new_key), 16)))[2:]
                encrypted_or_decrypted_message.append(bits_swapped)
            continue

        # Checking if encryption or decryption has to be done. Flipping bits after the xor operation in the decryption
        # part.
        if encrypt_or_decrypt == 'encrypt':
            new_key = key_for_encrypt_with_power2_and_task4(new_key, plain_text_hex_chunks,
                                                            encrypted_or_decrypted_message, x, encrypt_or_decrypt)
            encrypted_or_decrypted_message.append(hex_xor(plain_text_hex_chunks_bits_swapped[x], new_key))
        else:

            new_key = key_for_encrypt_with_power2_and_task4(new_key, plain_text_hex_chunks,
                                                            encrypted_or_decrypted_message, x, encrypt_or_decrypt)
            bits_swapped = hex(swap_every_second_bit(int(hex_xor(plain_text_hex_chunks[x], new_key), 16)))[2:]
            encrypted_or_decrypted_message.append(bits_swapped)

    # Joining the hex chunks then converting them to string.
    return hex2string(''.join(encrypted_or_decrypted_message))



# Ref: Canvas - "Week 5. - Practice" - "KissMark_week_5.py"
#       - https://canvas.elte.hu/courses/21877/assignments/149434
#           -> 4-byte version extended to handle 8 bytes.
#
# Task 5
# Create a new scheme, that uses the previous scheme as a substep. The  encryption algorithm working with 8 byte length
# keys. Run for the 1,9,17...th bytes the previous encryption with the first byte of the key. Run for the 2,10,18...th
# bytes the previous encryption with the second byte of the key. etc. similarly for the 8 bytes of the key.
#
# That means this algoritms splits up the input to 8 new inputs and feeds those 8 inputs for the previous scheme that
# uses only one byte length key.
def encrypt_with_power_and_swap_every_second_bit_8byte(plain_text, key, encrypt_or_decrypt):
    '''
    >>> key1 = [1,2,3,4,5,6,7,8]
    >>> key2 = [34,76,87,98,33,99,1,234]
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte('Hello',key1,'encrypt'))
    '85989f989a'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte(hex2string('acc5522cca'),key1,'encrypt'))
    '5dc8a218c0'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte(hex2string('acc5522cca'),key2,'encrypt'))
    '7e86f67ee4'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte(hex2string('1234123123'),key2,'encrypt'))
    '0374765032'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte(hex2string('5646234325'),key2,'encrypt'))
    '8bc544e13b'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte('I love Cryptography!!!',key1,'encrypt'))
    '87129f9bbc9c178bf8b2b9a886bf80d26184e7666302'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte("To be, or not to be, that is the question: Whether 'tis nobler in the mind to suffer",key1,'encrypt'))
    'a99d13959f1a1797e514948fa13489df8081cb7361a8f5fd98723792f1cc55bb6436fbdb722817de0d25912a15eed115f48b304cd006a278d9bbb10ddad831d68d00dab5ff01dffff3b894f9463132abddfd8a30'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte('Hello world, now I can encpryt with longer key!!',key1,'encrypt'))
    '85989f989a16bc97f998910c09b9aefb509641bfe38d71edbdda112157d6d1eaf869d5625ddb1c3ade1091531ba67c53'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte('Our goal is to test out if our algorithm working well with splitting the input.',key1,'encrypt'))
    '8eb8b2149e9995945f92ba00a1bb21f8fba3e930eeaad96457eab1bf5bc4d1021d32dede57c115ff7c2a1e9016a7f55a809af5ddf771fb1798d53132095de1d1cc17dce8a139c58b80ff1c19dbccbc'
    >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Hello',key1,'encrypt'),key1,'decrypt')
    'Hello'
    >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Hello',key2,'encrypt'),key2,'decrypt')
    'Hello'
    >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Hello',key1,'encrypt'),key1,'decrypt')
    'Hello'
    >>> string2hex(encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Hello',key1,'encrypt'),key2,'decrypt'))
    '5be8c4f577'
    >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Cryptography',key1,'encrypt'),key1,'decrypt')
    'Cryptography'
    >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte("To be, or not to be, that is the question: Whether 'tis nobler in the mind to suffer",key1,'encrypt'),key1,'decrypt')
    "To be, or not to be, that is the question: Whether 'tis nobler in the mind to suffer"
    >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Hello world, now I can encpryt with longer key!!',key1,'encrypt'),key1,'decrypt')
    'Hello world, now I can encpryt with longer key!!'
    >>> encrypt_with_power_and_swap_every_second_bit_8byte(encrypt_with_power_and_swap_every_second_bit_8byte('Our goal is to test out if our algorithm working well with joining the chunks.',key1,'encrypt'),key1,'decrypt')
    'Our goal is to test out if our algorithm working well with joining the chunks.'
    '''

    # Splitting the plain message according to the task requirements. So in the first chunk goes the plain text's 1st,
    # 9th, 17th character, in the second goes the 2nd, 10th, 18th, in the third goes the 3rd, 11th, 19th, and so on.
    first_chunk = [plain_text[x] for x in range(0, len(plain_text), 8)]
    second_chunk = [plain_text[x] for x in range(1, len(plain_text), 8)]
    third_chunk = [plain_text[x] for x in range(2, len(plain_text), 8)]
    fourth_chunk = [plain_text[x] for x in range(3, len(plain_text), 8)]
    fifth_chunk = [plain_text[x] for x in range(4, len(plain_text), 8)]
    sixth_chunk = [plain_text[x] for x in range(5, len(plain_text), 8)]
    seventh_chunk = [plain_text[x] for x in range(6, len(plain_text), 8)]
    eighth_chunk = [plain_text[x] for x in range(7, len(plain_text), 8)]

    # Encrypting the chunks with the proper given key. So the for the first chunk the first key, for the second, the
    # second key, and so on.
    first_chunk_encrypted = encrypt_with_power_and_swap_every_second_bit(''.join(first_chunk), key[0],
                                                                         encrypt_or_decrypt)
    second_chunk_encrypted = encrypt_with_power_and_swap_every_second_bit(''.join(second_chunk), key[1],
                                                                          encrypt_or_decrypt)
    third_chunk_encrypted = encrypt_with_power_and_swap_every_second_bit(''.join(third_chunk), key[2],
                                                                         encrypt_or_decrypt)
    fourth_chunk_encrypted = encrypt_with_power_and_swap_every_second_bit(''.join(fourth_chunk), key[3],
                                                                          encrypt_or_decrypt)
    fifth_chunk_encrypted = encrypt_with_power_and_swap_every_second_bit(''.join(fifth_chunk), key[4],
                                                                         encrypt_or_decrypt)
    sixth_chunk_encrypted = encrypt_with_power_and_swap_every_second_bit(''.join(sixth_chunk), key[5],
                                                                         encrypt_or_decrypt)
    seventh_chunk_encrypted = encrypt_with_power_and_swap_every_second_bit(''.join(seventh_chunk), key[6],
                                                                           encrypt_or_decrypt)
    eighth_chunk_encrypted = encrypt_with_power_and_swap_every_second_bit(''.join(eighth_chunk), key[7],
                                                                          encrypt_or_decrypt)
    chunks_joined = []
    ind_first = 0
    ind_second = 0
    ind_third = 0
    ind_fourth = 0
    ind_fifth = 0
    ind_sixth = 0
    ind_seventh = 0
    ind_eighth = 0
    range_len = len(first_chunk_encrypted) + len(second_chunk_encrypted) + len(third_chunk_encrypted)\
                + len(fourth_chunk_encrypted) + len(fifth_chunk_encrypted) + len(sixth_chunk_encrypted)\
                + len(seventh_chunk_encrypted) + len(eighth_chunk_encrypted)

    # Getting back to the original order (after chunking). I used modulo for this, as it seemed the easiest way
    # to determine which chunk's character has to be put into the joined chunk.
    for x in range(range_len):
        if x % 8 == 0 and not ind_first >= len(first_chunk_encrypted):
            chunks_joined.append(first_chunk_encrypted[ind_first])
            ind_first += 1
        elif x % 8 == 1 and not ind_second >= len(second_chunk_encrypted):
            chunks_joined.append(second_chunk_encrypted[ind_second])
            ind_second += 1
        elif x % 8 == 2 and not ind_third >= len(third_chunk_encrypted):
            chunks_joined.append(third_chunk_encrypted[ind_third])
            ind_third += 1
        elif x % 8 == 3 and not ind_fourth >= len(fourth_chunk_encrypted):
            chunks_joined.append(fourth_chunk_encrypted[ind_fourth])
            ind_fourth += 1
        elif x % 8 == 4 and not ind_fifth >= len(fifth_chunk_encrypted):
            chunks_joined.append(fifth_chunk_encrypted[ind_fifth])
            ind_fifth += 1
        elif x % 8 == 5 and not ind_sixth >= len(sixth_chunk_encrypted):
            chunks_joined.append(sixth_chunk_encrypted[ind_sixth])
            ind_sixth += 1
        elif x % 8 == 6 and not ind_seventh >= len(seventh_chunk_encrypted):
            chunks_joined.append(seventh_chunk_encrypted[ind_seventh])
            ind_seventh += 1
        elif x % 8 == 7 and not ind_eighth >= len(eighth_chunk_encrypted):
            chunks_joined.append(eighth_chunk_encrypted[ind_eighth])
            ind_eighth += 1

    # Joining the list of joined chunks into one string.
    return ''.join(chunks_joined)


# Task 6
# Your target company tried to transfer a secret html document (https://www.w3schools.com/html/html_intro.asp
# (Links to an external site.)) to another node, but you was able to catch the data. Your task to find out what
# is the secret. You know they used a really old non-secure crypto solution, so you confidently say you will be able
# to decrypt. The encryption algorithm is the previously implemented algorithm.

def create_possible_keys(ind, catched_stream):

    # In order to avoid redundancy, lists are created here for the possible keys based on the index
    # (which byte - 1 .. 8) in this function. So the keys list contains every possible key that could
    # be used for decryption.
    if ind == 1:
        keys = [[x, 0, 0, 0, 0, 0, 0, 0] for x in range(255)]
    elif ind == 2:
        keys = [[0, x, 0, 0, 0, 0, 0, 0] for x in range(255)]
    elif ind == 3:
        keys = [[0, 0, x, 0, 0, 0, 0, 0] for x in range(255)]
    elif ind == 4:
        keys = [[0, 0, 0, x, 0, 0, 0, 0] for x in range(255)]
    elif ind == 5:
        keys = [[0, 0, 0, 0, x, 0, 0, 0] for x in range(255)]
    elif ind == 6:
        keys = [[0, 0, 0, 0, 0, x, 0, 0] for x in range(255)]
    elif ind == 7:
        keys = [[0, 0, 0, 0, 0, 0, x, 0] for x in range(255)]
    elif ind == 8:
        keys = [[0, 0, 0, 0, 0, 0, 0, x] for x in range(255)]

    # Way of thinking: a simple HTML document starts with the "<!DOCTYPE html>" command. Since in the
    # encrypt_with_power_and_swap_every_second_bit_8byte() function I create the chunks so that in the
    # first chunk I put the message's first character, in the second chunk the second character, and so on.
    # I check, e.g. if the decrypted message starts with the character '<'. If the condition is satisfied, it
    # means that I have found a possible key for the first byte. There might be more possible keys, but as I
    # found out later in this task, fortunately there were only 1 proper possible key for every byte.
    possible_keys = []
    for key in keys:
        message = encrypt_with_power_and_swap_every_second_bit_8byte(hex2string(catched_stream), key, 'decrypt')
        if message[0] == '<' and ind == 1:
            possible_keys.append(key)
        elif message[1] == '!' and ind == 2:
            possible_keys.append(key)
        elif message[2] == 'D' and ind == 3:
            possible_keys.append(key)
        elif message[3] == 'O' and ind == 4:
            possible_keys.append(key)
        elif message[4] == 'C' and ind == 5:
            possible_keys.append(key)
        elif message[5] == 'T' and ind == 6:
            possible_keys.append(key)
        elif message[6] == 'Y' and ind == 7:
            possible_keys.append(key)
        elif message[7] == 'P' and ind == 8:
            possible_keys.append(key)

    return possible_keys


def decrypt_secret_message(catched_stream):

    # Since the task required to use the encrypt_with_power_and_swap_every_second_bit_8byte() function, we need
    # 8 bytes to decrypt the message. For this, I created the create_possible_keys() function that filters out
    # every possible key for the bytes.
    possible_first_keys = create_possible_keys(1, catched_stream)
    possible_second_keys = create_possible_keys(2, catched_stream)
    possible_third_keys = create_possible_keys(3, catched_stream)
    possible_fourth_keys = create_possible_keys(4, catched_stream)
    possible_fifth_keys = create_possible_keys(5, catched_stream)
    possible_sixth_keys = create_possible_keys(6, catched_stream)
    possible_seventh_keys = create_possible_keys(7, catched_stream)
    possible_eighth_keys = create_possible_keys(8, catched_stream)

    # As we can see, the filtering algorithm found only 1 possible key for every byte (the filtering method explained
    # in the create_possible_keys() function), so I simply chose the proper indices for the lists containing the
    # possible keys and put the together into one list (possible_keys_8byte).
    print(possible_first_keys, possible_second_keys, possible_third_keys, possible_fourth_keys, possible_fifth_keys,
          possible_sixth_keys, possible_seventh_keys, possible_eighth_keys)

    possible_keys_8byte = [possible_first_keys[0][0], possible_second_keys[0][1], possible_third_keys[0][2],
                           possible_fourth_keys[0][3], possible_fifth_keys[0][4], possible_sixth_keys[0][5],
                           possible_seventh_keys[0][6], possible_eighth_keys[0][7]]

    # After finding out the key, I can decrypt the catched stream with the
    # encrypt_with_power_and_swap_every_second_bit_8byte() function using the "decrypt" parameter.
    message = encrypt_with_power_and_swap_every_second_bit_8byte(hex2string(catched_stream), possible_keys_8byte, 'decrypt')
    return message


print(decrypt_secret_message('26457dfc0a7e73902e81ed11cf78046c8499af0d9c2c25a6fad95c1df9aad98cdabc42ce0c9947e4efb32903c27a9e284fbcc8dbf91830e06b8208bc2c813e08575cccaaa672f2fe52708abc001232259190d499baa3d89e19b3e2d1c44511bf0c07e039e5b6008ffca6dc2cee0599f18c44'))

# After the decryption, I got this Simple HTML Document:
#
# CONFIDENTAL
# The secret is: "rFesWX6b7kR9tg5C"
