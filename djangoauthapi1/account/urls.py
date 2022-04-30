from django.urls import path, include
from account.views import UserLoginView, UserRegistrationView, UserProfileView,UserChangePasswordView, SendResetPasswordLinkOnEmailView, UserResetPasswordView
from rest_framework.routers import DefaultRouter
from account.views import get_current_user_details

# router = DefaultRouter()
# router.register('profile', UserProfileView, basename="profile")

urlpatterns = [
  path('register/', UserRegistrationView.as_view(), name="register"),
  path('login/', UserLoginView.as_view(), name="login"),
  path('userprofile/', UserProfileView.as_view(), name="profile"),
  #path('', include(router.urls)),
  path('profile/', get_current_user_details, name="profile"),
  path('change-password/', UserChangePasswordView.as_view(), name="changepassword"),
  path('send-reset-password-email/', SendResetPasswordLinkOnEmailView.as_view(), name="resetpasswordlinksendonemail"),
  path('reset-password/<uid>/<token>/', UserResetPasswordView.as_view(), name="resetpassword"),
]