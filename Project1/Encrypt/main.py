import base64
import json
import hashlib
import rsa
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP

def genKeyRSA():
    (Kpublic, Kprivate) = rsa.newkeys(526)
    return Kpublic, Kprivate

def encryptRSA(string, pubKey):
    cipherText = rsa.encrypt(string.encode(), pubKey)
    return cipherText

def decryptRSA(string, privKey):
    plainText = rsa.decrypt(string, privKey)
    plainText = plainText.decode()
    return plainText


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

def hashSHA1(message):
    sha1 = hashlib.sha1(message).hexdigest()
    return sha1
    

def hashSHA256(message):
    sha256 = hashlib.sha256(message).hexdigest()
    return sha256
    


def Encrypt(plain_file_name):
    # gen 24 byte key length
    Ks = genKeyAES(24)
    # AES encrypt and write in ciphertext.json
    encAES(plain_file_name, 'ciphertext.json', Ks)

    # gen RSA public and private key
    Kpub, Kpriv = genKeyRSA()

    # encrypt AES key and caculate hash value
        # convert Ks to string
    strKs = base64.b64encode(Ks).decode('utf-8')
    Kx = encryptRSA(strKs, Kpub)

    # Hash Kprivate         
    strKpriv = str(Kpriv.n) + str(Kpriv.d)
    HKprivate = hashSHA1(strKpriv.encode('utf-8'))

    # structure of encrypt information
    encrypt_infor = {
        'Kx': base64.b64encode(Kx).decode('utf-8'),
        'HKprivate': HKprivate
    }
    # open file and write
    with open('Encrypt_Information.json', 'w') as file:
        json.dump(encrypt_infor, file, indent=4)

    # structure of RSA private key
    privKey_infor = {
        'n': Kpriv.n,
        'e': Kpriv.e,
        'd': Kpriv.d,
        'p': Kpriv.p,
        'q': Kpriv.q,
    }

    # open file and write
    with open('PrivateKey_Information.json', 'w') as file:
        json.dump(privKey_infor, file, indent=4)



# genKey('key.json', 24) 
# encAES('message.json', 'ciphertext.json', 'key.json')
# decAES('ciphertext.json', 'plaintext.json', 'key.json')

# def main():
#     None

# if __name__ == '__main__':
#     main()

Encrypt('message.json')

# Phần này tui giải một vài chổ để test
with open('PrivateKey_Information.json', 'r') as file:
    data = json.load(file)
    n = data['n']
    e = data['e']
    d = data['d']
    p = data['p']
    q = data['q']

private_key = rsa.PrivateKey(
    n = n,
    e = e,
    d = d,
    p = p,
    q = q
)

with open('Encrypt_Information.json', 'r') as file:
    data = json.load(file)
    keyAES = data['Kx']
    hashKey = data['HKprivate']

byteKeyAES = base64.b64decode(keyAES.encode('utf-8'))
Ks = decryptRSA(byteKeyAES, private_key)
bytes_Ks = base64.b64decode(Ks.encode('utf-8'))

strKpriv = str(private_key.n) + str(private_key.d)
HKpriv = hashSHA1(strKpriv.encode('utf-8'))
print(hashKey)
print(HKpriv)
