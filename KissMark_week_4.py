# We have encrypted a text message wtih xor encryption and repeating single byte key.
# Find out what is the key that used for the encprytion.
# Write the original text (that has been encrypted) to the end of a code in comment.
# Upload the whole created code that you were using to solve the assignment.

# The encrypted hex: e9c88081f8ced481c9c0d7c481c7ced4cfc581ccc480


def string2hex(_input):

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

    string2hex_list = []
    for x in _input:
        string2hex_list.append(hex(ord(x))[2:])
    return ''.join(string2hex_list)


def hex2string(_input):

    '''
    >>> hex2string('61')
    'a'
    >>> hex2string('776f726c64')
    'world'
    >>> hex2string('68656c6c6f')
    'hello'
    '''

    _input_sliced = [_input[x:x + 2] for x in range(0, len(_input), 2)]
    hex2string_list = []
    for x in range(len(_input_sliced)):
        hex2string_list.append(chr(int(_input_sliced[x], 16)))
    return ''.join(hex2string_list)


def fillupbyte(binary):
    target_length = len(binary) + (8 - len(binary) % 8) % 8
    return binary.zfill(target_length)


def character_xor(a, b):
    if a == b:
        return 0
    else:
        return 1


def hex_xor(_input1, _input2):

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

    _input = fillupbyte(bin(int(_input1, 16))[2:])
    _key = fillupbyte(bin(int(_input2, 16))[2:])
    if len(_input) > len(_key):
        _key = _key.zfill(len(_input))
    elif len(_input) < len(_key):
        _input = _input.zfill(len(_key))
    character_xor_list = []
    for a, b in zip(_input, _key):
        character_xor_list.append(character_xor(a, b))
    encrypted = '0b' + ''.join(str(x) for x in character_xor_list)
    return hex(int(encrypted, 2))[2:].zfill((len(str(_input2))))


def encrypt_single_byte_xor(_input, _key):

    '''
    >>> encrypt_single_byte_xor('aaabbccc','00')
    'aaabbccc'
    >>> encrypt_single_byte_xor('68656c6c6f','aa')
    'c2cfc6c6c5'
    >>> hex2string(encrypt_single_byte_xor(encrypt_single_byte_xor(string2hex('hello'),'aa'),'aa'))
    'hello'
    >>> hex2string(encrypt_single_byte_xor(encrypt_single_byte_xor(string2hex('Encrypt and decrypt are the same'),'aa'),'aa'))
    'Encrypt and decrypt are the same'
    '''

    return hex_xor(_input, _key)