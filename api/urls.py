from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.urls import path
from . import views

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('get-private-key/<str:user_code>', views.SendPrivateKey.as_view(), name='get_private_key'),
    path('send-private-key/', views.RecievePrivateKey.as_view(), name='send_private_key'),
]