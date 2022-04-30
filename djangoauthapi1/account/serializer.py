from rest_framework import serializers
from account.models import User
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from account.baseurl import BASEURL
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util


# For User Registration
class UserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
        )

    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    
    # password confirm field is needed for registration 
    password2 = serializers.CharField(style={'input_type':'password'},write_only=True,) 
    
    class Meta:
        model = User
        fields = ["email","name","password", "password2","tc"]
        # extra_kwargs = {
        #     'password':{'write_only':True}
        # } 

    # validating password and confirm password while registration
    def validate(self, attrs):
        if len(attrs.get('name')) < 3 or len(attrs.get('name')) > 20:
            raise serializers.ValidationError("name must be b/w 3 to 20 char")
       
        pass1 = attrs.get('password')
        pass2 = attrs.get('password2')
        
        if pass1 != pass2:
            raise serializers.ValidationError("password and confirm password does not match")
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

# For User Login
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ["email", "password"]

# For User Profile
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "name", "tc", "created_at"]

#Change Password
class UserChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ["password","password2"]

    def validate(self, attrs):
        new_pass = attrs.get('password')
        conf_pass = attrs.get('password2')
        user = self.context.get('user')
        
        if new_pass != conf_pass:
            raise serializers.ValidationError("password and confirm password does not match")       
        
        user.set_password(new_pass)
        user.save()
        return attrs

#Password Reset Link Send On Mail Serializer
class SendResetPasswordLinkOnEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email']
    
    def validate(self, attrs):
        
        # checking given email exist or not in the db
        if User.objects.filter(email=attrs['email']).exists():
           
            user = User.objects.get(email=attrs['email'])
            print("user",user)

            #print("user email",user['email'])
           
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("encode uid",uid)
            print("decode uid",int(urlsafe_base64_decode(uid)))
           
            token = PasswordResetTokenGenerator().make_token(user)
            print("token",token)
            
            link = BASEURL+"api/user/reset/"+uid+"/"+token
            print("link",link) 

            #make email body here
            body = "Click Following Link to Reset Your Password:\n"+link
            
            #make email data here
            data = {'subject':"Reset Your Password", 'body':body, 'to':user}
            
            #send mail to the user
            Util.send_mail(data)
        else:
            raise serializers.ValidationError("you are not a register user")
        return attrs

#Reset Password 
class UserResetPasswordSerializer(serializers.ModelSerializer):
    try:
        password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
        password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
        
        class Meta:
            model = User
            fields = ["password","password2"]

        def validate(self, attrs):
            new_pass = attrs.get('password')
            conf_pass = attrs.get('password2')
            
            #password matching check here
            if new_pass != conf_pass:
                raise serializers.ValidationError("password and confirm password does not match")

            #get the encode uid 
            uid = self.context.get('uid')
            
            #get the token
            token = self.context.get('token')
            
            #decode the encoded uid here
            decode_uid = smart_str(urlsafe_base64_decode(uid))
            print("decoded uid is",decode_uid)

            #get the user using decode uid
            user = User.objects.get(id=decode_uid)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Token is not valid or expired.")
                
            user.set_password(new_pass)
            user.save()
            return attrs
    
    except DjangoUnicodeDecodeError:
       raise serializers.ValidationError("Token is not valid or expired.")