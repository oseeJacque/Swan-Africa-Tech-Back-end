from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import check_password
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema

from .models import User
from .serializers import UserLoginSerializer, UserRegistrationSerializer, SendPasswordResetEmailSerializer, \
    UserChangePasswordSerializer, UserPasswordResetSerializer
from rest_framework_simplejwt.tokens import RefreshToken


def get_tokens_for_user(user):
    """
    This function use to get token for User when he is registering
    :param user: (user: Any)
    :return:  dict[str, str]
    """
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer

    def post(self, request, *args, **kwargs):
        """
        We redefine the post function for UserRegistrationView.It's being used to  save a new user register
        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({"token": token, "msg": "Registration successful"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserLoginView(APIView):
    serializer_class = UserLoginSerializer

    @swagger_auto_schema(
        operation_description="Endpoint Login",
        request_body=UserLoginSerializer
    )

    def post(self,request,format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = User.objects.get(email=email)
        print(user)
        #user = authenticate(email=email, password=password)

        if user is not None:
            if check_password(password, user.password):
                token = get_tokens_for_user(user)
                print(user.password)
                return Response({'token': token, 'msg': 'Login Sucess'}, status=status.HTTP_200_OK)

        return Response({'errors': {'non_field_errors': ['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)


#Send mail to get password
class SendPasswordResetEmailView(APIView):
    serializer_class = SendPasswordResetEmailSerializer

    @swagger_auto_schema(
        operation_description="Endpoint Login",
        request_body=SendPasswordResetEmailSerializer

    )
    def post(self,request,format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': "Password Reset Sucessfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#Change password from user
class UserChangePasswordView(APIView):
    serializer_class = UserChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Endpoint Login",
        request_body=UserChangePasswordSerializer

    )
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': "Password changed"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserPasswordResetView(APIView):
    serializer_class = UserPasswordResetSerializer

    @swagger_auto_schema(
        operation_description="Changement de password",
        request_body=UserPasswordResetSerializer

    )
    def post(self, request, uid, token, format=None):
        serializer=UserPasswordResetSerializer(data=request.data, context={'uid': uid, "token": token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':"Password Reset Sucessfully"},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)