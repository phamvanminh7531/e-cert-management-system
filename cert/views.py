from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
import qrcode
from django.urls import reverse
from io import BytesIO
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from account.models import User
from .models import CertHeader, Cert
from django.conf import settings
import json
from blockchain.node import Node
from blockchain.transaction import Transaction
from blockchain.utils import verifyMerkleProof

def error_page(request):
    return render(request, 'cert/error_page.html')

# Create your views here.
@login_required(login_url='account_app:login')
def home(request):
    user = request.user
    context = {}
    if user.is_teacher == True:
        cert_headers = CertHeader.objects.filter(teacher = User.objects.get(id = user.id), is_signed_all = False)
        signed_cert_header = CertHeader.objects.filter(teacher = User.objects.get(id = user.id), is_signed_all = True)
        context['cert_headers'] = cert_headers
        context['signed_cert_header'] = signed_cert_header
        return render(request, 'cert/teacher_home.html', context=context)
    elif user.is_admin == True:
        teacher_list = User.objects.filter(is_teacher = True)
        student_list = User.objects.filter(is_student = True)
        cert_header_list = CertHeader.objects.all()
        context['teacher_list'] = teacher_list
        context['student_list'] = student_list
        context['cert_header_list'] = cert_header_list
        return render(request, 'cert/admin_home.html', context=context)
    elif user.is_student:
        BLOCKCHAIN_NETWORK = settings.BLOCKCHAIN_NETWORK
        user_txids = Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).get_user_txids(user_code = user.user_code)
        cert_list = [Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).get_transaction(txid = txid) for txid in user_txids["txids"]]
        context["student"] = user
        cert = {}
        cert_list_2 = []
        for cert in cert_list:
            cert["header"] = CertHeader.objects.get(id = cert["transaction"]["data"]["cert_id"])
            cert["cert"] = cert
            cert_list_2.append(cert)
        context["cert_list"] = cert_list_2
        return render(request, 'cert/student_home.html', context=context)
    else:
        return redirect('account_app:logout')

@login_required(login_url='account_app:login')
def add_student(request):
    if request.method == "POST":
        user_code = request.POST.get('user_code')
        password = request.POST.get('password')
        full_name = request.POST.get('full_name')
        
        date_of_birth = request.POST.get('date_of_birth')

        if user_code and password:
            try:
                user = User.objects.create_user(user_code = user_code, password = password, full_name = full_name, date_of_birth = date_of_birth,  is_student = True)
            except:
                pass
            finally:
                return redirect('cert_app:home')
        else:
            return redirect('cert_app:home')

@login_required(login_url='account_app:login')
def add_teacher(request):
    if request.method == "POST":
        user_code = request.POST.get('user_code')
        password = request.POST.get('password')
        full_name = request.POST.get('full_name')
        date_of_birth = request.POST.get('date_of_birth')

        if user_code and password:
            try:
                user = User.objects.create_user(user_code = user_code, password = password, full_name = full_name, date_of_birth = date_of_birth,  is_teacher = True)
            except:
                pass
            finally:
                return redirect('cert_app:home')
        else:
            return redirect('cert_app:home')

@login_required(login_url='account_app:login')
def add_cert_header(request):
    if request.method == "POST":
        teacher = User.objects.get(id = request.POST.get('teacher_id'))
        name = request.POST.get('cert_name')
        uploaded_file = request.FILES['uploaded_file']
        CertHeader(subject_name = name, teacher = teacher, logo_image = uploaded_file).save()
        return redirect('cert_app:home')

@login_required(login_url='account_app:login')
def cert_detail(request, pk):
    context = {}
    student_list = User.objects.filter(is_student = True)
    cert_header = CertHeader.objects.get(id = pk)
    cert_list = cert_header.cert_set.all()
    context["cert_header"] = cert_header
    context["cert_list"] = cert_list
    context['student_list'] = student_list
    return render(request, 'cert/cert_detail.html', context=context)

@login_required(login_url='account_app:login')
def add_cert(request, pk):
    if request.method == "POST":
        cert_header = CertHeader.objects.get(id = pk)
        student = User.objects.get(id = request.POST.get('student_id'))
        try:
            mark = request.POST.get('mark')
        except:
            mark = None
        cert_data = {}
        if mark != None:
            cert_data["cert_id"] = cert_header.id
            cert_data["cert_name"] = cert_header.subject_name
            cert_data["student_code"] = student.user_code
            cert_data["student_name"] = student.full_name
            cert_data["teacher_code"] = cert_header.teacher.user_code
            cert_data["teacher_name"] = cert_header.teacher.full_name
            cert_data["type"] = "mark"
            cert_data["mark"] = mark
            Cert(cert_header = cert_header, cert_data = cert_data).save()
            return redirect(request.META.get('HTTP_REFERER'))
        else:
            cert_data["cert_id"] = cert_header.id
            cert_data["cert_name"] = cert_header.subject_name
            cert_data["student_code"] = student.user_code
            cert_data["student_name"] = student.full_name
            cert_data["teacher_code"] = cert_header.teacher.user_code
            cert_data["teacher_name"] = cert_header.teacher.full_name
            cert_data["type"] = "no-mark"
            Cert(cert_header = cert_header, cert_data = cert_data).save()
            return redirect(request.META.get('HTTP_REFERER'))

@login_required(login_url='account_app:login')
def teacher_cert_detail(request, pk):
    context = {}
    print(request.session.get('user_code'))
    cert_header = CertHeader.objects.get(id = pk)
    cert_list = cert_header.cert_set.all()
    context["cert_list"] = cert_list
    context["cert_header"] = cert_header
    return render(request, 'cert/teacher_cert_detail.html', context=context)

@login_required(login_url='account_app:login')
def teacher_sign_cert_header(request, pk):
    BLOCKCHAIN_NETWORK = settings.BLOCKCHAIN_NETWORK
    cert_header = CertHeader.objects.get(id = pk)
    user_code = request.session.get('user_code')
    teacher = User.objects.get(user_code = user_code)
    if cert_header.teacher.user_code == user_code:
        public_key = teacher.public_key
        f = teacher.private_key.open('r')
        private_key = RSA.import_key(f.read())
        signer = PKCS1_v1_5.new(private_key)
        cert_list = cert_header.cert_set.all()
        for cert in cert_list:
            if cert.is_signed == False:
                try:
                    transaction_data_byte = json.dumps(cert.cert_data, indent=2).encode('utf-8')
                    hasher = SHA256.new(transaction_data_byte)
                    signature = signer.sign(hasher).hex()
                    cert.cert_data["signature"] = signature
                    cert.cert_data["public_key"] = public_key
                    cert.save()
                    transaction = Transaction(cert.cert_data)
                    Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).send_transaction({"transaction": transaction.transaction_data, "sender": "e-cert-management-sys"})
                except:
                    continue
                cert.is_signed = True
                cert.save()
            else:
                continue
        else:
            cert_header.is_signed_all = True
            cert_header.save()
        return redirect('cert_app:home')
    else:
        return redirect('cert_app:error_page')

@login_required(login_url='account_app:login')
def explorer(request):
    context = {}
    if request.method == "POST":
        BLOCKCHAIN_NETWORK = settings.BLOCKCHAIN_NETWORK
        BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"] = request.POST.get('hostname')
        return redirect(request.META.get('HTTP_REFERER'))
    else:
        BLOCKCHAIN_NETWORK = settings.BLOCKCHAIN_NETWORK
        
        try:
            blockchain_list = Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).get_blockchain()
            transactions_in_pool = Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).get_pool()
            data_node_list = Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).known_node_request()
            BLOCKCHAIN_NETWORK["DATA_NODES"] = data_node_list
            context["blockchain"] = json.dumps(blockchain_list, indent=2)
            context["pool"] = json.dumps(transactions_in_pool, indent=2)
        except:
            BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"] = BLOCKCHAIN_NETWORK["FIRST_KNOW_NODE_HOSTNAME"]
            blockchain_list = Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).get_blockchain()
            transactions_in_pool = Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).get_pool()
            context["blockchain"] = json.dumps(blockchain_list, indent=2)
            context["pool"] = json.dumps(transactions_in_pool, indent=2)
            
        context["BLOCKCHAIN_NETWORK"] = BLOCKCHAIN_NETWORK

        return render(request, 'cert/explorer.html', context=context)

def cert_verify(request, txid):
    context = {}
    try:
        BLOCKCHAIN_NETWORK = settings.BLOCKCHAIN_NETWORK
        cert = Node(hostname=BLOCKCHAIN_NETWORK["CURRENT_CONNECT_NODE"]).get_transaction(txid = txid)
        if verifyMerkleProof(cert["transaction"]["txid"], cert["merkle_proof"], cert["merkle_root"]) == True:
            context["cert"] = cert["transaction"]["data"]
            absolute_url = request.build_absolute_uri('/')
            app2_detail_url = reverse('cert_app:cert_verify', kwargs={'txid': txid})
            qr_image = qrcode.make(absolute_url + app2_detail_url, box_size=2)
            qr_image_pil = qr_image.get_image()
            stream = BytesIO()
            qr_image_pil.save(stream, format='PNG')
            qr_image_data = stream.getvalue()
            qr_image_base64 = base64.b64encode(qr_image_data).decode('utf-8')
            context['qr_image_base64'] = qr_image_base64
            context['txid'] = txid
        else:
            return redirect('cert_app:error_page')
    except:
        return redirect('cert_app:error_page')
    return render(request, 'cert/cert_verify.html', context=context)