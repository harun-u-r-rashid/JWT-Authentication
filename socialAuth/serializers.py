from rest_framework import serializers
from .utils import Google, register_social_user

from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed


class GoogleSignInSerializer(serializers.Serializer):
    access_token=serializers.CharField()


    def validate_access_token(self, access_token):
        user_data=Google.validate(access_token)
        try:
            user_data['sub']
            
        except:
            raise serializers.ValidationError("this token has expired or invalid please try again")
        
        if user_data['aud'] != settings.GOOGLE_CLIENT_ID:
                raise AuthenticationFailed('Could not verify user.')

        user_id=user_data['sub']
        # username = user_data['email'].split('@')[0]
        email=user_data['email']
        first_name=user_data['given_name']
        last_name=user_data['family_name']
        provider='google'
        # print(user_id, username)

        return register_social_user(provider, email, first_name, last_name) #, username
