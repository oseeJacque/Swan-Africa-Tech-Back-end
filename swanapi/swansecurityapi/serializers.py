from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import User
from .utils import Util
from django.core.mail import send_mail


#User  serializer
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': "password"}, write_only=True)
    class Meta:
        model = User
        fields = ["lastname", "firstname", 'email',"telephone", "password", "password2"]
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError('Password and Confirm Password doesn\'t match')
        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password2')
        user = User.objects.create_user(**validated_data)
        return user



class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ["email", "password"]



class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': "password"}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': "password"}, write_only=True)

    class Meta:
        fields = ['password', "password2"]

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get("password2")
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and confirm Password doesn\'t match")
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')

        if User.objects.filter(email=email).exists:
            user = User.objects.get(email=email)
            #Encode the uid
            uid = urlsafe_base64_encode(force_bytes(user.id))
            #reset token for the user
            token = PasswordResetTokenGenerator().make_token(user)
            print(f"tokenn", token)

            #let's send the mail to user
            body = "Hello my frinds"
            data = {
                'subject': "Reset Yout Password ",
                "body": body,
                "to_email": user.email
            }
            Util.send_mail(data)
            #send_mail("Reset Yout Password", "Click this link to change your mail", "oseesoke@gmail.com", [f"{user.email}"])
            return attrs
        else:
            raise ValidationError("You are not a Registered User")



class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': "password"}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': "password"}, write_only=True)

    class Meta:
        fields = ['password', "password2"]

    def validate(self, attrs):
       try:
           password = attrs.get('password')
           password2 = attrs.get('password2')
           uid = self.context.get('uid')
           token = self.context.get('token')

           if password != password2:
               raise serializers.ValidationError('Password and Confirm Password doesn\'t match')
           id = smart_str(urlsafe_base64_decode(uid))
           user = User.objects.get(id=id)
           if not PasswordResetTokenGenerator().check_token(user, token):
               raise ValidationError('Token is not valid or expired')

           user.set_password(password)
           user.save()
           return attrs

       except DjangoUnicodeDecodeError as identifier:
           PasswordResetTokenGenerator().check_token(user,token)
           raise ValidationError('Token is not valid')

