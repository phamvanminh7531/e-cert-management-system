from django.urls import path, include
from .views import get_data_node


app_name = 'blockchain_app'

urlpatterns = [
    path('get-data-node/', get_data_node , name="get_data_node"),
]
