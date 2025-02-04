import base64
import json
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import rsa
import hashlib

#AES
def genKeyAES(mode):
    # Get random "mode" bytes length key
    key = Random.get_random_bytes(mode)
    return key

def encAES(mess_file_name, cipher_file_name, bytes_key):
    # get message and covert to bytes message
    with open(mess_file_name, 'r') as file:
        data = json.load(file)
        mess = data['message']
        bytes_mess = mess.encode('utf-8') 

    # encrypt
    cipher = AES.new(bytes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(bytes_mess)
    nonce = cipher.nonce

    # convert to string and write in file json
    data = {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8')
    }

    # open file and write
    with open(cipher_file_name, 'w') as file:
        json.dump(data, file, indent=4)

def decAES(cipher_file_name, plain_file_name, bytes_key):
    # get ciphertext, tag, nonce and convert from string to bytes
    with open(cipher_file_name, 'r') as file:
        data = json.load(file)
        ciphertext = data['ciphertext'] 
        bytes_ciphertext = base64.b64decode(ciphertext.encode('utf-8'))

        tag = data['tag'] 
        bytes_tag = base64.b64decode(tag.encode('utf-8'))

        nonce = data['nonce'] 
        bytes_nonce = base64.b64decode(nonce.encode('utf-8'))

    # decrypt 
    cipher = AES.new(bytes_key, AES.MODE_EAX, bytes_nonce)
    plaintext = cipher.decrypt_and_verify(bytes_ciphertext, bytes_tag)

    # open file, convert to string and write
    with open(plain_file_name, 'w') as file:
        data = {
            'message': plaintext.decode('utf-8')
        }
        json.dump(data, file, indent=4) 

#RSA
def genKeyRSA():
    (Kpublic, Kprivate) = rsa.newkeys(2048)
    return Kpublic, Kprivate

def encryptRSA(string, pubKey):
    cipherText = rsa.encrypt(string.encode(), pubKey)
    return cipherText

def decryptRSA(string, privKey):
    plainText = rsa.decrypt(string, privKey)
    plainText = plainText.decode()
    return plainText

#HASH FUNCTION
def hashSHA1(message):
    sha1 = hashlib.sha1(message).hexdigest()
    return sha1
    
def hashSHA256(message):
    sha256 = hashlib.sha256(message).hexdigest()
    return sha256

