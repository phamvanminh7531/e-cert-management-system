from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.urls import path
from . import views

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('get-public-key/<str:user_code>', views.GetPublicKey.as_view(), name='get_public_key'),
    path('get-private-key/', views.SendPrivateKey.as_view(), name='get_private_key'),
    path('delete-private-key/', views.DeletePrivateKey.as_view(), name='delete_teacher_private_key'),
    path('sign-cert/<str:pk>', views.TeacherSign.as_view(), name='teacher_sign'),
]