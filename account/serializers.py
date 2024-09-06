from rest_framework import serializers
from .models import Account
from .utils import send_email_to_reset_password
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, force_str, smart_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class UserRegSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(required=True)

    class Meta:
        model = Account
        fields = [
            "first_name",
            "last_name",
            "email",
            "password",
            "confirm_password",
        ]

    def save(self):
        first_name = self.validated_data["first_name"]
        last_name = self.validated_data["last_name"]
        email = self.validated_data["email"]

        password = self.validated_data["password"]
        confirm_password = self.validated_data["confirm_password"]

        if password != confirm_password:
            raise serializers.ValidationError({"error": "Password doesn't match"})

        if Account.objects.filter(email=email).exists():
            raise serializers.ValidationError({"error": "Email already exists"})

        account = Account(
            email=email,
            first_name=first_name,
            last_name=last_name,
        )
        account.set_password(password)
        account.is_active = False
        account.save()

        return account


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=155, min_length=6)
    password=serializers.CharField(max_length=68, write_only=True)
    full_name=serializers.CharField(max_length=255, read_only=True)
    access_token=serializers.CharField(max_length=255, read_only=True)
    refresh_token=serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = Account
        fields = ['email', 'password', 'full_name', 'access_token', 'refresh_token']

    

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request=self.context.get('request')
        user = authenticate(request, email=email, password=password)
        if not user:
            raise AuthenticationFailed("invalid credential try again")
        if not user.is_active:
            raise AuthenticationFailed("Email is not active")
        tokens=user.tokens()
        return {
            'email':user.email,
            'full_name':user.get_full_name,
            "access_token":str(tokens.get('access')),
            "refresh_token":str(tokens.get('refresh'))
        }
    
    

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ["email"]

    def validate(self, attrs):
        email = attrs.get("email")
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))

            token = PasswordResetTokenGenerator().make_token(user)
            request = self.context.get("request")
            current_site = get_current_site(request).domain
            relative_link = reverse(
                "reset-password-confirm", kwargs={"uidb64": uidb64, "token": token}
            )
            abslink = f"http://{current_site}{relative_link}"
            print("abslink", abslink)
            email_body = (
                f"Hi {user.first_name} use the link below to reset your password"
            )

            data = {
                "email_body": email_body,
                "email_subject": "Reset your password",
                "to_email": user.email,
            }

            send_email_to_reset_password(data)

        return super().validate(attrs)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=20, min_length=10, write_only=True)
    confirm_password = serializers.CharField(
        max_length=20, min_length=10, write_only=True
    )
    uidb64 = serializers.CharField(min_length=1, write_only=True)
    token = serializers.CharField(min_length=3, write_only=True)

    class Meta:
        fields = ["password", "confirm_password", "uidb64", "token"]

    def validate(self, attrs):
        try:
            token = attrs.get("token")
            uidb64 = attrs.get("uidb64")
            password = attrs.get("password")
            confirm_password = attrs.get("confirm_password")

            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = Account.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("Invalid")

            if password != confirm_password:
                raise AuthenticationFailed("Password doesn't match")

            user.set_password(password)
            user.save()
            return user

        except Exception as e:
            return AuthenticationFailed("Link is invalid or expired")
        return super().validate(attrs)


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    default_error_messages = {"bad_token": ("Token is expired or invalid")}

    def validate(self, attrs):
        self.token = attrs.get("refresh_token")

        return attrs

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            return self.fail("bad_token")
