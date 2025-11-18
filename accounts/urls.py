from django.urls import path, include
from .views import *

urlpatterns=[
    # path("", index, name="index"),
    path("",index ,name="index"),
    path('signup/',signup, name='signup'),
    path('login/',user_login, name='login'),
    path('forgot-password/',forgot_password, name='forgot_password'),
    path('resend-email/',resend_email, name='resend_email'),
    path('reset-complete/',reset_complete, name='reset_complete'),
    path('password_reset_confirm/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
]
