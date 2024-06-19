import requests
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.core.files.storage import FileSystemStorage
from django.db import models
from rest_framework.views import APIView
from .models import FileToken
from .serializers import FileTokenSerializer
from web3 import Web3
from cryptography.fernet import Fernet
import os
import json
import base64
from django.core.files.base import ContentFile
from django.conf import settings

# Configurar URLs de Alchemy
alchemy_url_eth = 'https://eth-sepolia.g.alchemy.com/v2/GiExCFEkalG3rleHyqQBC7_F94XjSFN7'
alchemy_url_polygon = 'https://polygon-amoy.g.alchemy.com/v2/MY7Lf3ia08BVIzbNHv2cnw1XUOwiWjDt'

# Conectar a Web3
w3_eth = Web3(Web3.HTTPProvider(alchemy_url_eth))
w3_polygon = Web3(Web3.HTTPProvider(alchemy_url_polygon))

# Pinata API Key (JWT)
PINATA_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiIwY2MxNjJlYS1kZmMyLTQ0ZGUtYjI2Ny05YjM4ZjNjM2MzOWIiLCJlbWFpbCI6ImNhcmxvc2cuYWx0YXJlam9zQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJwaW5fcG9saWN5Ijp7InJlZ2lvbnMiOlt7ImlkIjoiRlJBMSIsImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxfSx7ImlkIjoiTllDMSIsImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxfV0sInZlcnNpb24iOjF9LCJtZmFfZW5hYmxlZCI6ZmFsc2UsInN0YXR1cyI6IkFDVElWRSJ9LCJhdXRoZW50aWNhdGlvblR5cGUiOiJzY29wZWRLZXkiLCJzY29wZWRLZXlLZXkiOiJmNzhlM2VhNDExNjc3ZjA5NTUwNiIsInNjb3BlZEtleVNlY3JldCI6ImJjNzE2YmNmYTIwNWU0ZDFlYTMyZDFhMWVhNWY5MWZkOThhOWQzNWRkOTZkZTQyMzk5MmI3ODkyYWYzYjIxYjUiLCJpYXQiOjE3MTg3NDMzMjZ9.o8TLnyncJJOiFgiSNONo9bPCZGN9DdTN4WvarsTA13Y'

# Gateway URL
PINATA_GATEWAY = "https://sapphire-brilliant-scorpion-895.mypinata.cloud"

def home(request):
    return render(request, 'home.html')

def generate_fernet_key(password):
    if len(password) < 32:
        password = password.ljust(32)
    elif len(password) > 32:
        password = password[:32]
    return base64.urlsafe_b64encode(password.encode())

def upload_file_form(request):
    return render(request, 'upload.html')

def upload_to_pinata(content, filename):
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        'Authorization': f'Bearer {PINATA_JWT}',
    }
    files = {
        'file': (filename, content)
    }
    response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        ipfs_hash = response.json()['IpfsHash']
        return ipfs_hash
    else:
        raise Exception(f"Failed to upload to Pinata: {response.json()}")

class TokenizeFileView(APIView):

    def post(self, request):
        file = request.FILES['file']
        blockchain = request.POST['blockchain']
        wallet_address = request.POST['wallet_address']
        contract_address = request.POST['contract_address']
        encryption_key = request.POST['encryption_key']

        if file.size > 2 * 1024 * 1024:
            return JsonResponse({'error': 'File size exceeds 2MB'}, status=400)

        # Encriptar el archivo
        fernet_key = generate_fernet_key(encryption_key)
        fernet = Fernet(fernet_key)
        encrypted_content = fernet.encrypt(file.read())

        # Subir el archivo encriptado a IPFS usando Pinata
        ipfs_hash = upload_to_pinata(encrypted_content, file.name)
        token_uri = f"{PINATA_GATEWAY}/ipfs/{ipfs_hash}"

        # Crear transacción para almacenar el hash en el contrato
        contract_abi = json.loads("""[
            {
                "constant": false,
                "inputs": [{"name": "recipient", "type": "address"}, {"name": "tokenURI", "type": "string"}],
                "name": "createToken",
                "outputs": [{"name": "", "type": "uint256"}],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]""")

        if blockchain == 'ethereum':
            w3 = w3_eth
        elif blockchain == 'polygon':
            w3 = w3_polygon
        else:
            return JsonResponse({'error': 'Invalid blockchain selected'}, status=400)

        contract = w3.eth.contract(address=contract_address, abi=contract_abi)
        nonce = w3.eth.get_transaction_count(wallet_address)

        transaction = contract.functions.createToken(wallet_address, token_uri).build_transaction({
            'chainId': 11155111 if blockchain == 'ethereum' else 80001,  # Sepolia or Mumbai
            'gas': 2000000,
            'gasPrice': w3.toWei('50', 'gwei'),
            'nonce': nonce,
        })

        # Aquí devolvemos la transacción sin firmar para que el cliente la firme
        return JsonResponse(transaction)

def view_token_form(request):
    return render(request, 'view_token.html')

def show_wallet(request):
    wallet_address = request.GET.get('wallet_address')

    file_tokens = FileToken.objects.filter(
        models.Q(ethereum_token_address__isnull=False) |
        models.Q(polygon_token_address__isnull=False)
    )

    tokens = []
    for token in file_tokens:
        if token.ethereum_token_address:
            tokens.append({
                'blockchain': 'Ethereum',
                'token_address': token.ethereum_token_address,
                'file_name': token.file.name
            })
        if token.polygon_token_address:
            tokens.append({
                'blockchain': 'Polygon',
                'token_address': token.polygon_token_address,
                'file_name': token.file.name
            })

    return render(request, 'select_token.html', {'tokens': tokens})

def view_token(request):
    token_address = request.POST.get('token_address')
    encryption_key = request.POST.get('encryption_key')

    # Convertir la clave de encriptación proporcionada a una clave Fernet válida
    if len(encryption_key) < 32:
        encryption_key = encryption_key.ljust(32)
    elif len(encryption_key) > 32:
        encryption_key = encryption_key[:32]
    encryption_key = base64.urlsafe_b64encode(encryption_key.encode())

    file_token = get_object_or_404(FileToken, models.Q(ethereum_token_address=token_address) | models.Q(
        polygon_token_address=token_address))

    file_path = file_token.file.path

    # Leer y descifrar el contenido del archivo
    with open(file_path, 'rb') as f:
        encrypted_content = f.read()

    fernet = Fernet(encryption_key)
    try:
        decrypted_content = fernet.decrypt(encrypted_content)
    except:
        return HttpResponse("Invalid encryption key", status=400)

    response = HttpResponse(decrypted_content, content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment; filename=%s' % os.path.basename(file_path)
    return response
