# In your Django views.py
from django.http import JsonResponse, HttpResponse
from account.models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
import json


# def send_private_key(request, user_code):
#     if request.method == 'GET':
#         try:
#             user = User.objects.get(user_code=user_code)
#             private_key = user.private_key.open('r')
#             return HttpResponse(private_key, content_type='application/x-pem-file')
#         except Exception as e:
#             return JsonResponse({'status': 'error', 'message': str(e)})
#     return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

class SendPrivateKey(APIView):
    def get(self, request, user_code):
        try:
            user = User.objects.get(user_code=user_code)
            private_key = user.private_key.open('r')
            return HttpResponse(private_key, content_type='application/x-pem-file')
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

class RecievePrivateKey(APIView):
    def post(self, request):
        try:
            data = json.loads(request.body)
            private_key = data.get('privateKey')
            print(private_key)
            return JsonResponse({'status': 'success'})
        except Exception as e:
             return JsonResponse({'status': 'error', 'message': str(e)})