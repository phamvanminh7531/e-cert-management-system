from django.urls import path, include
from .views import home, add_student, add_teacher, add_cert_header
from .views import cert_detail, add_cert, teacher_cert_detail, explorer, error_page
from .views import teacher_sign_cert_header, cert_verify, add_cert_by_file

app_name = 'cert_app'

urlpatterns = [
    path('', home , name="home"),
    path('error/', error_page , name="error_page"),
    path('explorer/', explorer , name="explorer"),
    path('add-student/', add_student , name="add_student"),
    path('add-teacher/', add_teacher , name="add_teacher"),
    path('add-cert-header/', add_cert_header , name="add_cert_header"),
    path('cert-detail/<str:pk>', cert_detail , name="cert_detail"),
    path('add-cert/<str:pk>', add_cert , name="add_cert"),
    path('add-cert-by-file/<str:pk>', add_cert_by_file , name="add_cert_by_file"),
    path('teacher-cert-detail/<str:pk>', teacher_cert_detail , name="teacher_cert_detail"),
    path('teacher-sign-cert-header/<str:pk>', teacher_sign_cert_header , name="teacher_sign_cert_header"),
    path('cert-verify/<str:txid>', cert_verify , name="cert_verify"),
]
