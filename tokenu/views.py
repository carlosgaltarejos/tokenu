from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.core.files.storage import FileSystemStorage
from django.db import models
from rest_framework.views import APIView
from .models import FileToken
from .serializers import FileTokenSerializer
from web3 import Web3
from solana.rpc.api import Client as SolanaClient
from cryptography.fernet import Fernet
import os
import json


def upload_file_form(request):
    return render(request, 'upload.html')


class TokenizeFileView(APIView):

    def post(self, request):
        file = request.FILES['file']
        blockchain = request.POST['blockchain']
        wallet_address = request.POST['wallet_address']
        encryption_key = request.POST['encryption_key'].encode()

        if file.size > 2 * 1024 * 1024:
            return JsonResponse({'error': 'File size exceeds 2MB'}, status=400)

        # Generate key for encryption
        fernet = Fernet(Fernet.generate_key())
        # Read file content and encrypt it
        file_content = file.read()
        encrypted_content = fernet.encrypt(file_content)

        # Save the encrypted file
        fs = FileSystemStorage()
        filename = fs.save(file.name, encrypted_content)
        file_url = fs.url(filename)
        file_path = os.path.join(settings.MEDIA_ROOT, filename)

        if blockchain == 'ethereum':
            token_address = self.tokenize_ethereum(file_path, wallet_address)
        elif blockchain == 'solana':
            token_address = self.tokenize_solana(file_path, wallet_address)
        elif blockchain == 'polygon':
            token_address = self.tokenize_polygon(file_path, wallet_address)
        else:
            return JsonResponse({'error': 'Invalid blockchain selected'}, status=400)

        file_token = FileToken.objects.create(
            file=file,
            ethereum_token_address=token_address if blockchain == 'ethereum' else None,
            solana_token_address=token_address if blockchain == 'solana' else None,
            polygon_token_address=token_address if blockchain == 'polygon' else None
        )
        serializer = FileTokenSerializer(file_token)
        return JsonResponse(serializer.data, status=201)

    def tokenize_ethereum(self, file_path, wallet_address):
        w3 = Web3(Web3.HTTPProvider('https://ropsten.infura.io/v3/YOUR_INFURA_PROJECT_ID'))
        if not w3.isConnected():
            raise ConnectionError("Failed to connect to Ropsten")

        contract_address = "0xYourContractAddress"
        contract_abi = json.loads("""[
            {
                "constant": false,
                "inputs": [{"name": "to", "type": "address"}],
                "name": "createToken",
                "outputs": [{"name": "", "type": "uint256"}],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]""")

        contract = w3.eth.contract(address=contract_address, abi=contract_abi)
        account = "0xYourAccountAddress"
        private_key = "YourPrivateKey"
        nonce = w3.eth.getTransactionCount(account)

        transaction = contract.functions.createToken(wallet_address).buildTransaction({
            'chainId': 3,
            'gas': 2000000,
            'gasPrice': w3.toWei('50', 'gwei'),
            'nonce': nonce
        })

        signed_txn = w3.eth.account.signTransaction(transaction, private_key=private_key)
        tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

        if tx_receipt['status'] == 1:
            token_id = contract.functions.tokenCounter().call() - 1
            token_address = contract.functions.ownerOf(token_id).call()
            return token_address
        else:
            raise Exception("Token creation failed")

    def tokenize_solana(self, file_path, wallet_address):
        solana_client = SolanaClient('https://api.devnet.solana.com')
        # Implementar tokenización en Solana Devnet usando wallet_address
        token_address = 'SolanaTokenAddress'
        return token_address

    def tokenize_polygon(self, file_path, wallet_address):
        w3 = Web3(Web3.HTTPProvider('https://rpc-mumbai.maticvigil.com'))
        # Implementar tokenización en Polygon Mumbai testnet usando wallet_address
        token_address = '0xTokenAddressForPolygon'
        return token_address


def view_token_form(request):
    return render(request, 'tokenu/view_token.html')


def show_wallet(request):
    wallet_address = request.GET.get('wallet_address')

    file_tokens = FileToken.objects.filter(
        models.Q(ethereum_token_address__isnull=False) |
        models.Q(solana_token_address__isnull=False) |
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
        if token.solana_token_address:
            tokens.append({
                'blockchain': 'Solana',
                'token_address': token.solana_token_address,
                'file_name': token.file.name
            })
        if token.polygon_token_address:
            tokens.append({
                'blockchain': 'Polygon',
                'token_address': token.polygon_token_address,
                'file_name': token.file.name
            })

    return render(request, 'tokenu/select_token.html', {'tokens': tokens})


def view_token(request):
    token_address = request.POST.get('token_address')
    encryption_key = request.POST.get('encryption_key').encode()

    file_token = get_object_or_404(FileToken, models.Q(ethereum_token_address=token_address) | models.Q(
        solana_token_address=token_address) | models.Q(polygon_token_address=token_address))

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
