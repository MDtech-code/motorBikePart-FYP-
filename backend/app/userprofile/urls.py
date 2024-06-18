from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView
urlpatterns = [
    path('csrf_token/',views.CsrfTokenViews.as_view(),name='csrfToken'),
    path('signup/',views.SignupViews.as_view(),name='signup'),
    path('send_verify_email/',views.SendEmailVerificationView.as_view(),name='sendemailverify'),
    path ('verify_email/',views.EmailVerifyViews.as_view(),name='emailVerify'),
    path('login/',views.LoginViews.as_view(),name='login'),
    path('forget_password/',views.ForgetPasswordViews.as_view(),name='forgetPassword'),
    path('logout/',views.LogoutViews.as_view(),name='logout'),
    path('token/refresh/',TokenRefreshView.as_view(), name='token_refresh'),
    path('reset_password/',views.ResetPasswordView.as_view(),name='reset_password'),
]
