from rest_framework.response import Response
from rest_framework import status
from dj_rest_auth.registration.views import RegisterView
from chat.models import Setting
from allauth.account import app_settings as allauth_account_settings
from django.contrib.auth import get_user_model
from dj_rest_auth.views import LoginView
from dj_rest_auth.serializers import LoginSerializer
from rest_framework import serializers
User = get_user_model()
class RegistrationView(RegisterView):
    def create(self, request, *args, **kwargs):
        try:
            open_registration = Setting.objects.get(name='open_registration').value == 'True'
        except Setting.DoesNotExist:
            open_registration = True

        if open_registration is False:
            return Response({'detail': 'Registration is not yet open.'}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        data = self.get_response_data(user)

        data['email_verification_required'] = allauth_account_settings.EMAIL_VERIFICATION

        if data:
            response = Response(
                data,
                status=status.HTTP_201_CREATED,
                headers=headers,
            )
        else:
            response = Response(status=status.HTTP_204_NO_CONTENT, headers=headers)

        return response

class CustomLoginSerializer(LoginSerializer):
    username = serializers.CharField(required=True)
    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        # Check if input is an email address, if so, get the user by email
        if '@' in username:
            users = User.objects.filter(email__iexact=username)
        else:
            users = User.objects.filter(username__iexact=username)

        if not users or not users[0].check_password(password):
            raise serializers.ValidationError('Incorrect Email/Username or Password.')

        if not users[0].is_active:
            raise serializers.ValidationError('User is not active')

        attrs['user'] = users[0]
        return attrs


class CustomLoginView(LoginView):
    serializer_class = CustomLoginSerializer
    def finalize_response(self, request, response, *args, **kwargs):
        # 调用父类的方法获取最终的响应对象
        response = super().finalize_response(request, response, *args, **kwargs)

        # 取消HTTP Only标志
        if response.cookies.get('auth'):
            response.cookies['auth']['httponly'] = False

        return response