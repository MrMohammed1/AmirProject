from django.core.mail import send_mail
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.utils import timezone
from django.conf import settings
import random
from datetime import timedelta
from .models import UserOTP
from django.contrib.auth import authenticate
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .serializers import SignUpSerializer


def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(to_email, otp, subject="Your OTP for Account Verification"):
    message = f"Your OTP for account verification is: {otp}"
    from_email = settings.DEFAULT_FROM_EMAIL
    send_mail(subject, message, from_email, [to_email])

class SignUpView(APIView):
    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            otp = generate_otp()
            expiration_time = timezone.now() + timedelta(minutes=1)
            UserOTP.objects.create(user=user, otp=otp, expiration_time=expiration_time)
            send_otp_email(user.email, otp)
            return Response({"message": "User registered successfully. Please check your email for OTP."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class VerifyOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')  
        otp = request.data.get('otp') 

        try:
            user_otp = UserOTP.objects.get(user__email=email)
            
            if user_otp.expiration_time < timezone.now():
                return Response({
                    "message": "OTP has expired. Please request a new OTP.",
                    "request_new_otp": True
                }, status=status.HTTP_400_BAD_REQUEST)

            if user_otp.otp == otp:
                return Response({"message": "OTP verified successfully!"}, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        except UserOTP.DoesNotExist:
            return Response({"message": "OTP not found. Please register first."}, status=status.HTTP_400_BAD_REQUEST)


class RequestNewOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')

        try:
            user_otp = UserOTP.objects.get(user__email=email)

            if user_otp.expiration_time < timezone.now():
                otp = generate_otp()
                expiration_time = timezone.now() + timedelta(minutes=1)

                user_otp.otp = otp
                user_otp.expiration_time = expiration_time
                user_otp.save()

                send_otp_email(user_otp.user.email, otp)

                return Response({
                    "message": "Your previous OTP was expired. A new OTP has been sent to your email."
                }, status=status.HTTP_200_OK)

            return Response({"message": "Your OTP is still valid."}, status=status.HTTP_200_OK)

        except UserOTP.DoesNotExist:
            return Response({"message": "Please register first."}, status=status.HTTP_400_BAD_REQUEST)



def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        password2 = request.POST['password2']
        email = request.POST['email']

        if password != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'signup.html', {'email': email, 'username': username})

        try:
            user = User.objects.create_user(username=username, password=password, email=email)
            user.save()

            otp = generate_otp()
            expiration_time = timezone.now() + timedelta(minutes=1)
            UserOTP.objects.create(user=user, otp=otp, expiration_time=expiration_time)
            send_otp_email(user.email, otp)

            messages.success(request, "User registered successfully! Please check your email for OTP.")
            return redirect('verify_otp')
        except Exception as e:
            messages.error(request, str(e))
            return redirect('signup')

    return render(request, 'signup.html')



def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        password2 = request.POST['password2']
        email = request.POST['email']

        if password != password2:
            messages.error(request, "Passwords do not match.")
            return render(request, 'signup.html', {'email': email, 'username': username})

        try:
            user = User.objects.create_user(username=username, password=password, email=email)
            user.save()

            otp = generate_otp()
            expiration_time = timezone.now() + timedelta(minutes=1)
            UserOTP.objects.create(user=user, otp=otp, expiration_time=expiration_time)
            send_otp_email(user.email, otp)

            messages.success(request, "User registered successfully! Please check your email for OTP.")
            return redirect('verify_otp')
        except Exception as e:
            messages.error(request, str(e))
            return redirect('signup')

    return render(request, 'signup.html')


def verify_otp(request):
    if request.method == "POST":
        email = request.POST['email']
        otp = request.POST['otp']

        try:
            user_otp = UserOTP.objects.get(user__email=email)

            if user_otp.expiration_time < timezone.now():
                messages.error(request, "OTP has expired. Please request a new one.")
                return redirect('request_new_otp')

            if user_otp.otp == otp:
                messages.success(request, "OTP verified successfully!")
                return redirect('/admin/')
            else:
                messages.error(request, "Invalid OTP. Please try again.")
                return render(request, 'verify_otp.html', {'email': email})

        except UserOTP.DoesNotExist:
            messages.error(request, "OTP not found. Please check your email or register again.")
            return redirect('signup')

    return render(request, 'verify_otp.html')



def request_new_otp(request):
    if request.method == "POST":
        email = request.POST['email']

        try:
            user_otp = UserOTP.objects.get(user__email=email)

            if user_otp.expiration_time < timezone.now():
                otp = generate_otp()
                expiration_time = timezone.now() + timedelta(minutes=1)
                user_otp.otp = otp
                user_otp.expiration_time = expiration_time
                user_otp.save()

                send_otp_email(user_otp.user.email, otp)

                messages.success(request, "A new OTP has been sent to your email.")
                return redirect('verify_otp')
            else:
                messages.info(request, "Your OTP is still valid.")
                return redirect('verify_otp')

        except UserOTP.DoesNotExist:
            messages.error(request, "Please register first.")
            return redirect('signup')

    return render(request, 'request_new_otp.html')



class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user:
            otp = generate_otp()
            expiration_time = timezone.now() + timedelta(minutes=1)

            try:
                user_otp = UserOTP.objects.get(user=user)

                if user_otp.expiration_time < timezone.now():
                    user_otp.otp = otp
                    user_otp.expiration_time = expiration_time
                    user_otp.save()
                else:
                    return Response({
                        "message": "You already have a valid OTP. Please check your email."
                    }, status=status.HTTP_400_BAD_REQUEST)

            except UserOTP.DoesNotExist:
                UserOTP.objects.create(user=user, otp=otp, expiration_time=expiration_time)

            send_otp_email(user.email, otp)

            return Response({
                "message": "Login successful! Please check your email for OTP."
            }, status=status.HTTP_200_OK)

        return Response({
            "error": "Invalid credentials"
        }, status=status.HTTP_401_UNAUTHORIZED)



def login_view(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            try:
                user_otp = UserOTP.objects.get(user=user)

                if user_otp.expiration_time < timezone.now():
                    otp = generate_otp()
                    expiration_time = timezone.now() + timedelta(minutes=1)
                    user_otp.otp = otp
                    user_otp.expiration_time = expiration_time
                    user_otp.save()
                    
                    send_otp_email(user.email, otp)

                else:
                    messages.success(request, "You already have a valid OTP. Please check your email.")

                return redirect('verify_otp')

            except UserOTP.DoesNotExist:
                otp = generate_otp()
                expiration_time = timezone.now() + timedelta(minutes=1)
                UserOTP.objects.create(user=user, otp=otp, expiration_time=expiration_time)

                send_otp_email(user.email, otp)

                messages.success(request, "A new OTP has been sent to your email.")
                return redirect('verify_otp')

        else:
            messages.error(request, "Invalid credentials.")
            return redirect('login')

    return render(request, 'login.html')

