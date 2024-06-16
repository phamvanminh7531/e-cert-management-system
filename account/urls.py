from django.urls import path, include
from .views import login_page, download_private_key, logout_

app_name = 'account_app'

urlpatterns = [
    path('login/',login_page , name="login"),
    path('logout/', logout_ , name="logout"),
    # path('download-private-key/<str:user_code>', download_private_key , name="download_private_key"),
    # path('register/', register_page, name="register"),
    # path('logout/', logout_, name="logout"),
]
