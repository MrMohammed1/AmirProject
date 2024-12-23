from django.urls import path
from .views import *

urlpatterns = [
    # API-based views
    path('api/signup/', SignUpView.as_view(), name='api-signup'),
    path('api/verify-otp/', VerifyOTPView.as_view(), name='api-verify-otp'),
    path('api/request-new-otp/', RequestNewOTPView.as_view(), name='api-request-new-otp'),
    path('api/login/', LoginView.as_view(), name='api-login'),
    path('api/users/', UserListView.as_view(), name='user-list'),
    path('api/users/<int:pk>/', UserDetailView.as_view(), name='user-detail'),  


    # Function-based views
    path('signup/', signup, name='signup'),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('request_new_otp/', request_new_otp, name='request_new_otp'),
    path('login/', login_view, name='login'),
    path('users/', user_list, name='user-list'),
    path('users/<int:user_id>/edit/', user_edit, name='user-edit'),
    path('users/<int:user_id>/delete/', user_delete, name='user-delete'),
]


