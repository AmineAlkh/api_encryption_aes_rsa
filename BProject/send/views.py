from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.http.response import JsonResponse
from rest_framework.parsers import JSONParser 
from rest_framework import status
from .models import Food
from .serializers import FoodSerializer
import base64
import json
from Crypto.Random import get_random_bytes
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad
from .models import *


@api_view(['GET', 'POST', 'DELETE'])
def menu_view(request):
    '''API view to show, add or delete data'''
    # Show data
    if request.method == 'GET':
        menu = Food.objects.all()  
        menu_serializer = FoodSerializer(menu, many=True)
        return JsonResponse(menu_serializer.data, safe=False)
    # Add data
    elif request.method == 'POST':
        menu_data = JSONParser().parse(request)
        menu_serializer = FoodSerializer(data=menu_data)
        if menu_serializer.is_valid():
            menu_serializer.save()
            return JsonResponse(menu_serializer.data, status=status.HTTP_201_CREATED) 
        return JsonResponse(menu_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    # Delete data
    elif request.method == 'DELETE':
        count = Food.objects.all().delete()
        return JsonResponse({'message': '{} Foods were deleted successfully!'.format(count[0])}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
def send_menu(request):
    '''API to send menu data on port 8080'''
    # Get menu data, format it to str
    menu = Food.objects.all()  
    menu_serializer = FoodSerializer(menu, many=True).data
    data = json.dumps(menu_serializer)

    # A one time AES key to encrypt data with
    aes_key = generate_aes_key()
    # Encrypt key with rsa method
    encrypted_aes_key = rsa_encrypt(aes_key)
    # Format key so it can be added to header
    encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')

    # Encrypt data
    data = bytes(data, 'utf-8')    
    enc_data = aes_encrypt(data,aes_key)
    data = base64.b64encode(enc_data).decode('utf-8')

    # Define request header
    headers = {
        'Content-Type': 'application/json',
        'Encrypted-AesKey': encrypted_aes_key
    }

    # Define request payload
    data = {
        "encryptedData": data,

    }
    payload = json.dumps(data)

    return Response(payload, headers=headers)



def rsa_encrypt(aes_key):
    '''The receiver's project (AProject) would use the sender's public key to 
    encrypt the AES key, and then use their own private key to decrypt it'''
    # Load the sender's public key
    with open("public.pem", "rb") as f:
        sender_public_key = RSA.import_key(f.read())
    # Create a new RSA cipher object
    cipher = PKCS1_OAEP.new(sender_public_key)
    # Encrypt the AES key
    encrypted_aes_key = cipher.encrypt(aes_key)

    return encrypted_aes_key


def generate_aes_key():
    '''One time aes key'''
    return get_random_bytes(16)


# Function to encrypt a message using AES encryption in CBC mode
def aes_encrypt(message, key, key_size=256):
    # Pad the message to a multiple of the block size
    message = pad(message, block_size=16)
    # Generate a random initialization vector (IV)
    iv = Random.new().read(AES.block_size)
    # Create a new AES cipher object in CBC mode with the given key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Encrypt the message and prepend the IV to the result
    return iv + cipher.encrypt(message)



def generate_rsa_key():
    ''' Do this once before testing the API,
    Share one pair of the code with the other app.
    (does not matter which one) 
    '''
    # Generate a new RSA key pair
    key = RSA.generate(2048)
    # Save the private key to a file
    private_key = key.export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)
    #Save the public key to a file
    public_key = key.publickey().export_key()
    with open("public.pem", "wb") as f:
        f.write(public_key)
