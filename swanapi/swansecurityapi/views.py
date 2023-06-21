from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse
from rest_framework import generics, status
from rest_framework.decorators import authentication_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema

from .models import Users
from .serializers import UserLoginSerializer, UserRegistrationSerializer, SendPasswordResetEmailSerializer, \
    UserChangePasswordSerializer, UserPasswordResetSerializer, UserProfileSerializer, UpdateProfilePictureSerializer, \
    UpdateUserSerializer, ChangeEmailSerializer
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

@authentication_classes([])
class UserRegistrationView(generics.CreateAPIView):
    permission_classes = [AllowAny]
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


@authentication_classes([])
class UserLoginView(APIView):
    permission_classes = [AllowAny]

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
        user = Users.objects.get(email=email)
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


#Change password whan user is authenticated
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




#Change password when user forget it
class UserPasswordResetView(APIView):
    serializer_class = UserPasswordResetSerializer

    @swagger_auto_schema(
        operation_description="Changement de password",
        request_body=UserPasswordResetSerializer
    )

    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, "token": token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg': "Password Reset Sucessfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#View to get user Informations
class UserProfileView(APIView):

    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]
    def get(self,request,format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


#Update profilPicture views
class UpdateProfilePictureView(APIView):
    parser_classes = (FormParser, MultiPartParser)
    @swagger_auto_schema(
        operation_description="Update Profile",
        request_body=UpdateProfilePictureSerializer

    )

    def post(self, request):
        user = request.user
        serializer = UpdateProfilePictureSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "Profile picture updated"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


#Update profil  user profil view
class UpdateUserView(APIView):
    @swagger_auto_schema(
        operation_description="Mise a jour profile",

        request_body=UpdateUserSerializer,

    )
    def post(self, request):
      #  user_id = request.query_params.get('param')
       # if user_id is None:
        #    return Response({"error": "Missing 'param' parameter in the request"}, status=status.HTTP_400_BAD_REQUEST)
        # code for handling the GET request with the 'param'
        user = request.user
        if user is None:
            return Response({"error": "Assurez voud d'etre connecté"}, status=status.HTTP_400_BAD_REQUEST)
        serializer = UpdateUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangeEmailView(APIView):
    permission_classes = (IsAuthenticated,)

    @swagger_auto_schema(
        operation_description="Change email",

        request_body=ChangeEmailSerializer,

    )
    def put(self, request):
        serializer = ChangeEmailSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.update(request.user, serializer.validated_data)
            return Response({'message': 'Adresse e-mail mise à jour avec succès.'})
        return Response(serializer.errors, status=400)