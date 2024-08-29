from rest_framework import serializers
from .models import Students
import regex as re

class StudentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Students
        fields = ["id", "name", "age", "username", "address", "email"]

    def validate_name(self, value):
        if not re.match(r"^[\p{L}\s]*$", value, re.UNICODE):
            raise serializers.ValidationError("Name chỉ được chứa chữ cái và khoảng trắng")
        if len(value) < 2 or len(value) > 50:
            raise serializers.ValidationError("Name phải có độ dài từ 2 đến 50 ký tự")
        return value

    def validate_age(self, value):
        if value < 1 or value > 120:
            raise serializers.ValidationError("Age phải nằm trong khoảng từ 1 đến 120")
        return value

    def validate_username(self, value):
        if len(value) < 8 or len(value) > 16:
            raise serializers.ValidationError("Username phải có độ dài từ 8 đến 16 ký tự")
        if ' ' in value:
            raise serializers.ValidationError("Username không được có khoảng trống")
        if not re.match("^[A-Za-z0-9]*$", value):
            raise serializers.ValidationError("Username không được chứa ký tự đặc biệt")
        return value

    def validate_address(self, value):
        if len(value) < 10 or len(value) > 100:
            raise serializers.ValidationError("Address phải có độ dài từ 10 đến 100 ký tự")
        return value

    def validate_email(self, value):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", value):
            raise serializers.ValidationError("Email không hợp lệ")
        return value
