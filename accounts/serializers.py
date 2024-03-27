# users/serializers.py
import random

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from rest_framework import serializers, status

#
User = get_user_model()


# <editor-fold desc="User Registration">
class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'username', 'password', 'is_verified']

    def validate(self, data):
        email = data.get('email')
        username = data.get('username')

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                {"message": "Email already in use.", 'status': status.HTTP_400_BAD_REQUEST})

        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError(
                {"message": "Username already taken.", 'status': status.HTTP_400_BAD_REQUEST})

        return data

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        return user


# # </editor-fold>

# <editor-fold desc="verify otp">
class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.CharField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        email = data.get('email')
        otp = data.get('otp')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"message": "User does not exist", 'status': status.HTTP_400_BAD_REQUEST})

        if user.otp != otp:
            raise serializers.ValidationError({"message": "Invalid OTP", 'status': status.HTTP_400_BAD_REQUEST})

        return data

    def create(self, validated_data):
        user = User.objects.get(email=validated_data.get('email'))
        user.is_verified = True
        user.save()
        return user


# </editor-fold>

# <editor-fold desc="Login User with Otp">
class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        email = data.get('email')
        otp = data.get('otp')

        # Fetch user by email or username
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                "message": "Invalid email/username or OTP",
                "status": "error"
            })

        # Check OTP
        if user.otp != otp:
            raise serializers.ValidationError({
                "message": "Invalid OTP",
                "status": "error"
            })

        data['user'] = user
        return data


# </editor-fold>

# <editor-fold desc="Forgot Password">
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Check if the provided email exists in the database.
        """
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError({"message":"User with this email does not exist","status":status.HTTP_400_BAD_REQUEST})
        return value

    def save(self):
        """
        Trigger sending the password reset email.
        """
        email = self.validated_data['email']

        # Generate OTP
        otp = ''.join(random.choices('0123456789', k=6))

        # Save OTP to user (you may have your own way of storing OTP)
        user = User.objects.get(email=email)
        user.otp = otp
        user.save()

        # Send password reset email with OTP
        subject = "Password Reset OTP"
        message = f"Your OTP for password reset is: {otp}"
        send_mail(subject, message, settings.EMAIL_HOST_USER, [email])
# </editor-fold>

# <editor-fold desc="password reset">
class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    password = serializers.CharField(min_length=6)
    confirm_password = serializers.CharField(min_length=6)

    def validate(self, data):
        """
        Validate email, OTP, and password.
        """
        email = data.get('email')
        otp = data.get('otp')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        # Check if user exists with provided email
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"message": "User with this email does not exist", "status": "error"}, code='invalid')

        # Check if OTP matches
        if user.otp != otp:
            raise serializers.ValidationError({"message": "Invalid OTP", "status": "error"}, code='invalid')

        # Check if password and confirm_password match
        if password != confirm_password:
            raise serializers.ValidationError({"message": "Passwords do not match", "status": "error"}, code='invalid')

        data['user'] = user
        return data

    def create(self, validated_data):
        """
        Reset the user's password, send OTP to email, and save OTP on user.
        """
        user = validated_data['user']
        password = validated_data['password']

        # Update user's password
        user.set_password(password)
        user.save()

        # Generate OTP
        otp = ''.join(random.choices('0123456789', k=6))

        # Send OTP to user's email
        subject = "your Login  OTP"
        message = f"Your OTP is: {otp}"
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])

        # Save OTP on user
        user.otp = otp
        user.save()

        return user
# </editor-fold>
