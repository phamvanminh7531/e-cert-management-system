from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .models import User
from django.http import FileResponse

# Create your views here.
def login_page(request):
    if request.user.is_authenticated:
        return redirect('cert_app:home')
    else:
        if request.method == 'POST':
            user_code = request.POST.get('user_code')
            password =request.POST.get('password')

            user = authenticate(request, user_code=user_code, password=password)

            if user is not None:
                login(request, user)
                request.session['user_code'] = user.user_code
                return redirect('cert_app:home')
            else:
                messages.info(request, 'Username OR password is incorrect')

        context = {}
        return render(request, 'account/login.html', context)

def download_private_key(request, user_code):
    try:
        user = User.objects.get(user_code=user_code)
        return FileResponse(user.private_key, as_attachment=True)
    except:
        return redirect('cert_app:home')

def logout_(request):
    logout(request)
    return redirect('account_app:login')