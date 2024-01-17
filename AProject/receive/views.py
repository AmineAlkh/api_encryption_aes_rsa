from django.shortcuts import render
from django.http.response import HttpResponse
import requests
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# Create your views here.


def menu(request):
    '''Fetch data from BProject's API'''
    try:
        response = requests.get('http://localhost:8080/send')
        # Read data on payload, format it into dict and get the encrypted version
        data = json.loads(json.loads(response.content.decode('utf-8')))
        enc_data = data["encryptedData"]
        # Get the encrypted AES key from request header then change the format to bytes
        enc_aes_key_byte = base64.b64decode(response.headers.get("Encrypted-AesKey"))
        # Decrypting the AES key
        aes_key = rsa_dectypt(enc_aes_key_byte)
        # Decrypting data with key
        data = aes_decrypt(enc_data, aes_key)
        data = data.decode('utf-8')
        data = json.loads(data)
        # Pass the menu data to the template
        return render(request, 'menu.html', {'menu': data})
    except:
        return HttpResponse("No data!")

def aes_decrypt(enc_data, key):
   # Convert the base64 encoded string back into bytes
   enc_data = base64.b64decode(enc_data)
   # Extract the IV and the encrypted message
   iv = enc_data[:AES.block_size]
   message = enc_data[AES.block_size:]
   # Create a new AES cipher object in CBC mode with the given key and IV
   cipher = AES.new(key, AES.MODE_CBC, iv)
   # Decrypt the message and unpad it
   return unpad(cipher.decrypt(message), AES.block_size)


def rsa_dectypt(encrypted_aes_key):
    '''The sender's project (BProject) would use it's private key to decrypt the 
    aes '''
    # The sender sends the encrypted AES key along with the encrypted data
    # The receiver receives the encrypted AES key and uses their private key to decrypt it
    with open("private.pem", "rb") as f:
        receiver_private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(receiver_private_key)
    aes_key = cipher.decrypt(encrypted_aes_key)
    return aes_key

