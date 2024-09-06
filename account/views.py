from django.shortcuts import render
from .serializers import (
    UserRegSerializer,
    LoginSerializer,
    PasswordResetRequestSerializer,
    SetNewPasswordSerializer,
    LogoutSerializer,
)
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .utils import send_code_to_user
from rest_framework.permissions import AllowAny, IsAuthenticated
from .models import OneTimePassword
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .models import Account



class RegistrationView(APIView):
    serializer_classes = UserRegSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        print(request.data)

        user = request.data
        serializer = UserRegSerializer(data=user)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user_data = serializer.data

            send_code_to_user(user_data["email"])
            return Response(
                {
                    "data": user_data,
                    "message": "Thanks for signing up! A passcode has been sent to verify your email.",
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class VerifyUserEmail(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp_code = request.data.get("otp")
        try:
            user_code_obj = OneTimePassword.objects.get(code=otp_code)
            user = user_code_obj.account
            if not user.is_active:
                user.is_active = True
                user.save()
                return Response(
                    {"message": "Account email verified successfully!"},
                    status=status.HTTP_200_OK,
                )
            return Response(
                {"message": "Code is not valid"}, status=status.HTTP_204_NO_CONTENT
            )
        except OneTimePassword.DoesNotExist:
            return Response(
                {"message": "Passcode not provided"}, status=status.HTTP_400_BAD_REQUEST
            )
        
        
class LoginUserView(APIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        print("responce", request.data)
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PasswordResetRequestView(APIView):
    serializer_class = PasswordResetRequestSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(
            {"message": "we have sent you a link to reset your password"},
            status=status.HTTP_200_OK,
        )
        # return Response({'message':'user with that email does not exist'}, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirm(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = Account.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    {"message": "token is invalid or has expired"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            return Response(
                {
                    "success": True,
                    "message": "credentials is valid",
                    "uidb64": uidb64,
                    "token": token,
                },
                status=status.HTTP_200_OK,
            )

        except DjangoUnicodeDecodeError as identifier:
            return Response(
                {"message": "token is invalid or has expired"},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class SetNewPasswordView(APIView):
    serializer_class = SetNewPasswordSerializer
    permission_classes = [AllowAny]

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {"success": True, "message": "password reset is succesful"},
            status=status.HTTP_200_OK,
        )


class TestingAuthenticatedReq(APIView):
    permission_classes=[IsAuthenticated]

    def get(self, request):

        data={
            'msg':'its works'
        }
        return Response(data, status=status.HTTP_200_OK)



class LogoutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.data
        return Response(status=status.HTTP_200_OK)
