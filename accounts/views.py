from django.shortcuts import render,redirect
from django.contrib.auth import authenticate, login as auth_login
import random
import string
from django.core.mail import send_mail
from django.conf import settings
from . models import *
from django.db.models import Q
from rest_framework.authtoken.models import Token
from django.contrib.auth.views import PasswordResetView
from django.urls import reverse, reverse_lazy
from django.contrib.messages.views import SuccessMessageMixin
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode


# Create your views here.
# def index(request):
#     return HttpResponse("Hello, world. You're at the index.")

def index(request):
    return render(request, 'index.html')

def signup(request):
    if request.method=='POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        phone_number = request.POST.get('mobile')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if not first_name:
            return render(request, 'signup.html', {'message': "First name is required"})
        
        if not last_name:
            return render(request, 'signup.html', {'message': "Last name is required"})
        
        if not email:
            return render(request, 'signup.html', {'message': "Email is required"})
        
        if not phone_number:
            return render(request, 'signup.html', {'message': "Phone number is required"})
        
        if not password:
            return render(request, 'signup.html', {'message': "Password is required"})
        
        if not confirm_password:
            return render(request, 'signup.html', {'message': "Confirm password is required"})
        
        if password != confirm_password:
            return render(request, 'signup.html', {'message': "Passwords do not match"})

        if User.objects.filter(Q(email=email) | Q(phone_number=phone_number)).exists():
            return render(request, 'signup.html', {'message': "User is already registered"})
        
        user = User.objects.create_user(
            first_name=first_name,
            last_name=last_name,
            username=email,
            email=email,
            phone_number=phone_number,
            password=password
        )

        user.save()
        return redirect('login')

    return render(request, 'signup.html')

def user_login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        if not email:
            return render(request, 'login.html', {'message': "Email is required"})
        
        if not password:
            return render(request, 'login.html', {'message': "Password is required"})
        
        user = authenticate(request, username=email, password=password)

        if user is not None:
            token, created=Token.objects.get_or_create(user=user)
            auth_login(request,user)

            if user.is_superuser:
                return redirect('admin_dashboard')
            return redirect('home') 
        else:
            return render(request, 'login.html', {'message':"Invalid email or password"})

    return render(request, 'login.html')

def generate_unique_otp():
    while True:
        otp = ''.join(random.choices(string.digits, k=6))
        if not User.objects.filter(otp=otp).exists():
            return otp
        
# def send_otp_via_email(email, otp):
#     try:
#         subject = "hello"
#         message = f"email verify :{otp}"
#         email_from = settings.EMAIL_HOST_USER
#         recipient_list = [email]
#         send_mail(subject, message, email_from, recipient_list)
#     except Exception as e:
#         print(f"Error sending email: {e}")

# def forgot_password(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')

#         if not email:
#             return render(request, 'forgot_password.html', {'message': "Email is required"})

#         try:
#             user = User.objects.get(email=email)
#             otp = generate_unique_otp()
#             user.otp = otp
#             user.save()
#             send_otp_via_email(email, otp)
#             return render(request, 'resend_email.html', {'message': 'OTP sent successfully', 'message_type': 'success'})
#         except User.DoesNotExist:
#             return render(request, 'forgot_password.html', {'message': 'User not found. Please check your email or sign up.', 'message_type': 'error'})
    
#     return render(request, "forgot_password.html")

class ResetPasswordView(SuccessMessageMixin, PasswordResetView):
    template_name = 'password_reset_confirm.html'
    email_template_name = 'users/password_reset_confirm.html'
    subject_template_name = 'users/password_reset_subject'
    success_message = "We've emailed you instructions for setting your password, " \
                      "if an account exists with the email you entered. You should receive them shortly." \
                      " If you don't receive an email, " \
                      "please make sure you've entered the address you registered with, and check your spam folder."
    success_url = reverse_lazy('users-home')

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        if not email:
            return render(request, 'forgot_password.html', {'message': "Email is required"})

        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(str(user.pk).encode('utf-8'))
            path = reverse('password_reset_confirm', args=[uid, token])
            reset_link = f'http://192.168.100.241:8080{path}'
            
            send_mail(
                subject='Password Reset',
                message=f'Click here to reset your password: {reset_link}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            return render(request, 'resend_email.html', {'message': 'Password reset link sent successfully', 'message_type': 'success'})
        except User.DoesNotExist:
            return render(request, 'forgot_password.html', {'message': 'User not found. Please check your email or sign up.', 'message_type': 'error'})
    
    return render(request, "forgot_password.html")

def password_reset_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode('utf-8')
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password1 = request.POST.get('new_password')
            new_password2 = request.POST.get('confirm_new_password')

            if new_password1 == new_password2:
                user.set_password(new_password1)
                user.save()
                return redirect(reverse_lazy('reset_complete'))
            else:
                return render(request, 'password_reset_confirm.html', {'uidb64': uidb64, 'token': token, 'message': 'Passwords do not match'})
        else:
            return render(request, 'password_reset_confirm.html', {'uidb64': uidb64, 'token': token})
    else:
        return render(request, 'forgot_password.html', {'message': 'Invalid token', 'message_type': 'error'})
    
def resend_email(request):
    return render(request,"resend_email.html")

def reset_complete(request):
    return render(request,"reset_complete.html")