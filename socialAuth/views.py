from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from .serializers import GoogleSignInSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny


  

class GoogleOauthSignInview(GenericAPIView):
    serializer_class=GoogleSignInSerializer
    permission_classes=[AllowAny]

    def post(self, request):
        print(request.data)
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data=((serializer.validated_data)['access_token'])
        return Response(data, status=status.HTTP_200_OK) 
   
