from django.contrib import admin
from django.urls import path
from .views import (
    RegistrationView,
    VerifyUserEmail,
    LoginUserView,
    PasswordResetRequestView,
    PasswordResetConfirm,
    SetNewPasswordView,
    LogoutView,
    TestingAuthenticatedReq
)

from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("register/", RegistrationView.as_view(), name="register"),
    path("verify/", VerifyUserEmail.as_view(), name="verify"),
    path("login/", LoginUserView.as_view(), name="login"),
    path("password-reset/", PasswordResetRequestView.as_view(), name="password-reset"),
    path(
        "password-reset-confirm/<uidb64>/<token>/",
        PasswordResetConfirm.as_view(),
        name="reset-password-confirm",
    ),
    path("get-something/", TestingAuthenticatedReq.as_view(), name="just-for-testing"),
    path('token/refresh/', TokenRefreshView.as_view(), name='refresh-token'),
    path("set-new-password/", SetNewPasswordView.as_view(), name="set-new-password"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
