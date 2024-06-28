# In your Django views.py
from django.http import JsonResponse, HttpResponse
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from account.models import User
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
import json
from cert.models import Cert, CertHeader
from blockchain.node import Node
from blockchain.transaction import Transaction

class GetPublicKey(APIView):
    permission_classes = [AllowAny]
    def get(self, request, user_code):
        try:
            user = User.objects.get(user_code = user_code)
            public_key = user.public_key
            return Response({'user_code': user.user_code,'public_key': public_key}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_404_NOT_FOUND)

class SendPrivateKey(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            user = request.user
            private_key = user.private_key.open('r')
            return HttpResponse(private_key, content_type='application/x-pem-file')
        except Exception as e:
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_404_NOT_FOUND)

class DeletePrivateKey(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request):
        try:
            request.user.private_key.delete()
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

# class TeacherSign(APIView):
#     permission_classes = [IsAuthenticated]
#     def post(self, request, pk):
#         BLOCKCHAIN_NETWORK = settings.BLOCKCHAIN_NETWORK
#         cert_header = CertHeader.objects.get(id = pk)
#         teacher = request.user
#         if cert_header.teacher.user_code == teacher.user_code:
#             public_key = teacher.public_key
#             data = json.loads(request.body)
#             private_key = RSA.import_key(data.get('privateKey'))
#             signer = PKCS1_v1_5.new(private_key)
#             cert_list = cert_header.cert_set.all()
#             for cert in cert_list:
#                 if cert.is_signed == False:
#                     try:
#                         transaction_data_byte = json.dumps(cert.cert_data, indent=2).encode('utf-8')
#                         hasher = SHA256.new(transaction_data_byte)
#                         signature = signer.sign(hasher).hex()
#                         transaction = Transaction(data=cert.cert_data, signature=signature, public_key=public_key)
#                         response = Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).send_transaction({"transaction": transaction.transaction_data, "sender": "e-cert-management-sys"})
#                     except:
#                         continue
#                     if response.status_code == 200:
#                         cert.is_signed = True
#                         cert.save()
#                     else:
#                         break
#                 else:
#                     continue
#             else:
#                 cert_header.is_signed_all = True
#                 cert_header.save()
#                 return JsonResponse({'status': 'success'})
#         else:
#             return JsonResponse({'status': 'error'})

class TeacherSign(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        BLOCKCHAIN_NETWORK = settings.BLOCKCHAIN_NETWORK
        cert_header = CertHeader.objects.get(id=pk)
        teacher = request.user

        if cert_header.teacher.user_code != teacher.user_code:
            return JsonResponse({'status': 'error'})

        public_key = teacher.public_key
        data = json.loads(request.body)
        private_key = RSA.import_key(data.get('privateKey'))
        signer = PKCS1_v1_5.new(private_key)
        cert_list = cert_header.cert_set.all()

        for cert in cert_list:
            if not cert.is_signed:
                try:
                    transaction_data_byte = json.dumps(cert.cert_data, indent=2).encode('utf-8')
                    hasher = SHA256.new(transaction_data_byte)
                    signature = signer.sign(hasher).hex()
                    transaction = Transaction(data=cert.cert_data, signature=signature, public_key=public_key)
                    response = Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).send_transaction({
                        "transaction": transaction.transaction_data,
                        "sender": "e-cert-management-sys"
                    })

                    if response.status_code == 200:
                        cert.is_signed = True
                        cert.save()
                    else:
                        return JsonResponse({'status': 'error', 'message': 'Failed to send transaction'})
                except Exception as e:
                    return JsonResponse({'status': 'error', 'message': str(e)})

        cert_header.is_signed_all = True
        cert_header.save()
        return JsonResponse({'status': 'success'})

