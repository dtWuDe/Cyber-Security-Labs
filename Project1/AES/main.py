import base64
import json
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

def genKey(key_file_name, mode):
    key = Random.get_random_bytes(mode)

    data = {
        'key': base64.b64encode(key).decode('utf-8')
    }

    with open(key_file_name, 'w') as file:
        json.dump(data, file)


def encAES(mess_file_name, cipher_file_name, key_file_name):
    with open(mess_file_name, 'r') as file:
        data = json.load(file)
        mess = data['message']
        bytes_mess = base64.b64encode(mess.encode('utf-8'))

    with open(key_file_name, 'r') as file:
        data = json.load(file)
        key = data['key']
        bytes_key = base64.b64decode(key.encode('utf-8'))

    cipher = AES.new(bytes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(bytes_mess)
    nonce = cipher.nonce

    data = {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8')
    }

    with open(cipher_file_name, 'w') as file:
        json.dump(data, file)

def decAES(cipher_file_name, plain_file_name, key_file_name):
    with open(cipher_file_name, 'r') as file:
        data = json.load(file)
        ciphertext = data['ciphertext'] 
        bytes_ciphertext = base64.b64decode(ciphertext.encode('utf-8'))

        tag = data['tag'] 
        bytes_tag = base64.b64decode(tag.encode('utf-8'))

        nonce = data['nonce'] 
        bytes_nonce = base64.b64decode(nonce.encode('utf-8'))

    with open(key_file_name, 'r') as file:
        data = json.load(file)

        key = data['key']
        bytes_key = base64.b64decode(key.encode('utf-8'))

    cipher = AES.new(bytes_key, AES.MODE_EAX, bytes_nonce)
    plaintext = cipher.decrypt_and_verify(bytes_ciphertext, bytes_tag)
    print(base64.b64decode(plaintext))
    with open(plain_file_name, 'w') as file:
        data = {
            'message': base64.b64decode(plaintext).decode('utf-8')
        }
        json.dump(data, file) 

def hashSHA1(message):
    sha1 = hashlib.sha1(message).hexdigest()
    return sha1
    

def hashSHA256(message):
    sha256 = hashlib.sha256(message).hexdigest()
    return sha256
    

with open('message.json', 'r') as file:
    data = json.load(file)
    mess = data['message']
    bytes_mess = base64.b64encode(mess.encode('utf-8'))
    value = hashSHA256(bytes_mess)
    print(value)


# mode 16, 20, 14
# genKey('key.json', 24) 
# encAES('message.json', 'ciphertext.json', 'key.json')
# decAES('ciphertext.json', 'plaintext.json', 'key.json')