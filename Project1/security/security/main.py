import algorithm_module
import base64
import json
import rsa
import sys
import tkinter as tk
from tkinter import filedialog

#I. Encrypt file
def Encrypt(plain_file_name):
    # gen 24 byte key length
    Ks = algorithm_module.genKeyAES(24)
    # AES encrypt and write in ciphertext.json
    algorithm_module.encAES(plain_file_name, 'ciphertext.json', Ks)

    # gen RSA public and private key
    Kpub, Kpriv = algorithm_module.genKeyRSA()

    # encrypt AES key and caculate hash value
        # convert Ks to string
    strKs = base64.b64encode(Ks).decode('utf-8')
    Kx = algorithm_module.encryptRSA(strKs, Kpub)

    # Hash Kprivate         
    strKpriv = str(Kpriv.n) + str(Kpriv.d)
    HKprivate = algorithm_module.hashSHA1(strKpriv.encode('utf-8'))

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


#II. Decrypt file
def Decrypt(cipher_file_name):
    # Read the Kprivate file
    with open('PrivateKey_Information.json', 'r') as file:
        privKey = json.load(file)

    privateKey = rsa.PrivateKey(
        n = privKey['n'],
        e = privKey['e'],
        d = privKey['d'],
        p = privKey['p'],
        q = privKey['q']
    )

    # Read the HKprivate and Kx
    with open('Encrypt_Information.json', 'r') as file:
        data = json.load(file)
    # Access the specific variable
    Kx = data['Kx']
    HKprivate = data['HKprivate']

    # Check SHA-1 Kprivate hash value with HKprivate
        #Calculate hash SHA-1 Kprivate value
    strKpriv = str(privateKey.n) + str(privateKey.d)
    Hash_Kpriv = algorithm_module.hashSHA1(strKpriv.encode('utf-8'))

        #check
    if(HKprivate != Hash_Kpriv):
        return False
    else:
        Kxx = base64.b64decode(Kx.encode('utf-8'))
        Kss = algorithm_module.decryptRSA(Kxx, privateKey)
        Ks = base64.b64decode(Kss.encode('utf-8'))

    #Decrypt from C to P
    algorithm_module.decAES(cipher_file_name, 'plaintext.json', Ks)


def main():
    if sys.argv[1]== '-encrypt':
        #Encrypt
            #Select the file to encrypt
            print("Select the plain file to encrypt: ")

            # Create a new tkinter window
            window = tk.Tk()
            window.withdraw() # Hide the window

            # Prompt the user to choose a file
            file_path_Encrypt = filedialog.askopenfilename()

            # Get just the file name
            file_name_Encrypt = file_path_Encrypt.split('/')[-1]
            print(file_name_Encrypt)

            # Close the tkinter window
            window.destroy()

            if file_name_Encrypt == '':
                print('Not Found File Encrypt')
            else:
                Encrypt(file_name_Encrypt)
                print("Encrypt.......DONE")

    elif sys.argv[1] == '-decrypt':
        #Decrypt
            #Select the file to decrypt
            print("Select the cipher file to decrypt: ")
            # Create a new tkinter window
            window = tk.Tk()
            window.withdraw() # Hide the window

            # Prompt the user to choose a file
            file_path_Decrypt = filedialog.askopenfilename()

            # Get just the file name
            file_name_Decrypt = file_path_Decrypt.split('/')[-1]
            print(file_name_Decrypt)

            # Close the tkinter window
            window.destroy()

            if file_name_Decrypt == '':
                print('Not Found File Derypt')
            else:
                Decrypt(file_name_Decrypt)
                print("Decrypt.......DONE")



s = 'sdda'

k = algorithm_module.hashSHA1(s)

print(k)


