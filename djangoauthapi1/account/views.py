from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializer import UserChangePasswordSerializer, UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer,SendResetPasswordLinkOnEmailSerializer, UserResetPasswordSerializer
from django.contrib.auth import authenticate
from .renderer import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes, renderer_classes, throttle_classes
from rest_framework.throttling import UserRateThrottle


#Creating tokens manually using the user
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# User Registration
class UserRegistrationView(APIView):
        
    #custom render class assign to the login view
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        
        #pass user data in serializer
        serializer = UserRegistrationSerializer(data=request.data)
        
        #validate the user creadential
        serializer.is_valid(raise_exception=True)# it by default raise an error and return 400 bad request status to the client
        
        #save user in the db return the user
        user = serializer.save()

        #call the token generate method and pass the user
        token = get_tokens_for_user(user)
        return Response({"Token":token, "Message":"Registration Done"}, status=status.HTTP_201_CREATED)

# User Login
class UserLoginView(APIView):

    #custom render class assign to the login view
    renderer_classes = [UserRenderer]

    def post(self, request):
        
        #pass user data in serializer
        serializer = UserLoginSerializer(data=request.data)
        
        #validate the user creadential
        serializer.is_valid(raise_exception=True)# it by default raise an error and return 400 bad request status to the client
  
        #now authentication creadentials 
        user = authenticate(email=serializer.data['email'], password=serializer.data['password'])
        
        #check user is found or not
        if user is not None:
            #call the token generate method and pass the user
            token = get_tokens_for_user(user)
            
            return Response({"Token":token ,"Message":"Logged In"}, status=status.HTTP_200_OK)
        else:
            return Response({'errors':{"no_field_errors":["Invaild Creadential"]}}, status=status.HTTP_404_NOT_FOUND)

#custom thottle classes for user api
class ThousandPerDayUserThrottle(UserRateThrottle):
    rate = '100/day'
class TenPerDayUserThrottle(UserRateThrottle):
    rate = '10/day'

# current user details using function based view
@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
@renderer_classes([UserRenderer])
@throttle_classes([ThousandPerDayUserThrottle])
def get_current_user_details(request):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

# current user details using class based view 
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [TenPerDayUserThrottle]

    def get(self, request):
        print("current user", request.user)

        #pass user data in serializer
        serializer = UserProfileSerializer(self.request.user)
        
        print("serialized data", serializer.data)
        print("serialized data type", type(serializer.data))
        return Response(serializer.data, status=status.HTTP_200_OK)

# password change api 
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [TenPerDayUserThrottle]

    def post(self, request):
        print("req body", request.body)
        print("req data", request.data)
        serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
        serializer.is_valid(raise_exception=True)
        return Response({"Message":"Password Changed Successfully"},status=status.HTTP_200_OK)

# send reset password link on mail api
class SendResetPasswordLinkOnEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request):
        serializer = SendResetPasswordLinkOnEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"Message":"Reset Password Link is Send Your Email Please Check..."}, status=status.HTTP_200_OK)
        
# check user reset password view
class UserResetPasswordView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token):
        serializer = UserResetPasswordSerializer(data=request.data, context={'uid':uid, 'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({"Message":"Password Reset Successfully"}, status=status.HTTP_200_OK)