from django.urls import path
from .views import SignUpView, LoginView, signup, login_view

urlpatterns = [
    path('signup/', SignUpView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('register/', signup, name='register'),
    path('signin/', login_view, name='signin'),
]
