import hashlib
import itertools
import os

chars = 'abcdefghijklmnopqrstuvxyz'
users = {
    'admin': '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', #sha256('admin')
    'user': '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', #sha256('hello')
}
pepper_prefix = 'this_can_help_to_confuse_the_attacker_'
users_with_pepper = {
    'admin': {'passwordHash':'89e6b5ed137e3864d99ec9b421cf6f565d611f4c2b98e31a7d353d63aa748e9c'}, #sha256('this_can_help_to_confuse_the_attacker_admin')
    'user': {'passwordHash':'6dc765830e675d5fa4a9afb248be09a0407f6353d44652fd9b36038884a76323'}, #sha256('this_can_help_to_confuse_the_attacker_hello')
}
users_with_pepper_and_salt = {
    'admin': {'passwordHash':'d3eab7f4d6974f1db32b9cd9923fce9b434b28dc229b6582b845f1fca770d9f7', 'salt':"5294976873732394418"}, #sha256('this_can_help_to_confuse_the_attacker_admin5294976873732394418')
    'user': {'passwordHash':'976c73e0b408c89df3c1a12c3b0c45a6fee71bc1de5b47a88fae1a5e69ba6e28', 'salt':'1103733363818826232'}, #sha256('this_can_help_to_confuse_the_attacker_hello1103733363818826232')
}


def sha256(text):
    '''
    >>> sha256('I')
    'a83dd0ccbffe39d071cc317ddf6e97f5c6b1c87af91919271f9fa140b0508c6c'
    >>> sha256('love')
    '686f746a95b6f836d7d70567c302c3f9ebb5ee0def3d1220ee9d4e9f34f5e131'
    >>> sha256('crypto')
    'da2f073e06f78938166f247273729dfe465bf7e46105c13ce7cc651047bf0ca4'
    '''

    m = hashlib.sha256()
    m.update(bytes(text, 'ascii'))
    return m.hexdigest()


def authenticate(username, password):
    '''
    >>> authenticate('admin','admin')
    True
    >>> authenticate('admin','admin2')
    False
    >>> authenticate('user','hello')
    True
    >>> authenticate('user','helo')
    False
    '''

    password_hash = sha256(password)
    if users[username] == password_hash:
        return True

    return False


def hack_sha256_fixed_size(password_hash, length):
    '''
    >>> hack_sha256_fixed_size('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',5)
    'admin'
    >>> hack_sha256_fixed_size('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',5)
    'hello'
    >>> hack_sha256_fixed_size('a819d7cd38e9101be2e496298e8bf426ce9cdf78d2af35ddf44c6ad25d50158b',5)
    'crypt'
    >>> hack_sha256_fixed_size('688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6',3)
    'asd'
    >>> hack_sha256_fixed_size('7ec658e98073955c48314d0146593497a163d79f4e1dfea4bab03b79af227214',4)
    'elte'
    '''

    possible_passwords = [''.join(x) for x in itertools.product(chars, repeat=length)]
    for x in possible_passwords:
        if sha256(x) == password_hash:
            return x

    return None


def hack_sha256(password_hash):
    '''
    >>> hack_sha256('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918')
    'admin'
    >>> hack_sha256('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
    'hello'
    >>> hack_sha256('a819d7cd38e9101be2e496298e8bf426ce9cdf78d2af35ddf44c6ad25d50158b')
    'crypt'
    >>> hack_sha256('688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6')
    'asd'
    >>> hack_sha256('7ec658e98073955c48314d0146593497a163d79f4e1dfea4bab03b79af227214')
    'elte'
    '''

    for x in range(1, 11):
        password = hack_sha256_fixed_size(password_hash, x)
        if password is not None:
            return password

    return None


# Ref: GeeksforGeeks - How to store a password in database?
#
# As the article states the Rainbow Table can be used to reverse lookup the actual password by comparing the hashes
# obtained from the database. In other words, this table is a collection of hashes of most commonly used passwords.
# The only thing that has to be done is comparing the hashes to each other and when there are matches, the password
# can be reversed according to the corresponding hash.
#
# After several hours of looking, I was not able to find any words table which I could find the password with, so
# I used an online converter, which uses a huge database that involved these specific hashes. https://crackstation.net/
# This is how I would've done it if I had the proper database which involves these passwords.
def hack_sha256_longer(password_hash):

    f = open(os.path.join("D:\\RENDSZER\\Dokumentumok\\Egyetemi JEGYZETEK\\Proginf_msc\\1st_semester\\Computer Security\\Practice", "mostcommonlyusedpasswords.txt"), 'r')
    possible_passwords = f.read()
    f.close()

    for x in possible_passwords:
        if sha256(x) == password_hash:
            return x

    return None


print(hack_sha256_longer('e06554818e902b4ba339f066967c0000da3fcda4fd7eb4ef89c124fa78bda419')) # cryptography
print(hack_sha256_longer('8aa261cbc05ad6a49bea91521e51c8b979aa78215b8defd51fc0cebecc4d5c96')) # romeo and juliet
print(hack_sha256_longer('f2b826b18b9de86628dd9b798f3cb6cfd582fb7cee4ea68489387c0b19dc09c1')) # vulnerable


def authenticate_with_pepper_and_authenticate_with_pepper_and_salt(username, password, database, salt=''):

    password_hash = sha256(pepper_prefix + password + salt)
    if database[username]['passwordHash'] == password_hash:
        return True

    return False


def authenticate_with_pepper(username, password):
    '''
    >>> authenticate_with_pepper('admin','admin')
    True
    >>> authenticate_with_pepper('admin','admin2')
    False
    >>> authenticate_with_pepper('user','hello')
    True
    >>> authenticate_with_pepper('user','helo')
    False
    '''

    return authenticate_with_pepper_and_authenticate_with_pepper_and_salt(username, password, users_with_pepper)


def authenticate_with_pepper_and_salt(username, password):
    '''
    >>> authenticate_with_pepper_and_salt('admin','admin')
    True
    >>> authenticate_with_pepper_and_salt('admin','admin2')
    False
    >>> authenticate_with_pepper_and_salt('user','hello')
    True
    >>> authenticate_with_pepper_and_salt('user','helo')
    False
    '''

    salt = users_with_pepper_and_salt[username]['salt']
    return authenticate_with_pepper_and_authenticate_with_pepper_and_salt(username, password, users_with_pepper_and_salt, salt)
