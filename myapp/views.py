from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError,InvalidToken
from .models import Students
from .serializers import StudentsSerializer
from django.contrib.auth.hashers import make_password,check_password


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self,request):
        serializer = StudentsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(password=make_password(request.data.get('password')))
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self,request):
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            user = Students.objects.get(username=username)

            if check_password(password,user.password):
                refresh_token = RefreshToken.for_user(user)
                access_token = refresh_token.access_token

                access_token["id"] = user.id
                access_token["username"] = user.username
                
                return Response({
                    'id':user.id,
                    'username':user.username,
                    'access':str(access_token),
                    'refresh':str(refresh_token)
                })
            
            else:
                return Response({'error':'Tên đăng nhập hoặc mật khẩu không đúng'},status=status.HTTP_400_BAD_REQUEST)
            
        except Students.DoesNotExist:
            return Response({'error':'Sai Username'}, status=status.HTTP_401_UNAUTHORIZED)
        

class CustomJWTAuthentication(JWTAuthentication):
    def get_user(self,validated_token):
        try:
            user_id = validated_token.get('user_id')
            user = Students.objects.get(id=user_id)
            return user
        except Students.DoesNotExist:
            raise InvalidToken("User not found")
        

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CustomJWTAuthentication]

    def get(self, request):
        user = request.user
        serializer = StudentsSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class TokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self,request):
        refresh_token = request.data.get('refresh')
        try:
            token = RefreshToken(refresh_token)
            new_access_token = token.access_token
            return Response({
                'access':str(new_access_token),
                'refresh':str(token)
            })
        except TokenError as e:
            return Response({'error':str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CustomJWTAuthentication]

    def update_user(self, user, data):
        serializer = StudentsSerializer(instance=user, data=data, partial=True)

        if not serializer.is_valid():
            return serializer.errors, status.HTTP_400_BAD_REQUEST
        
        if 'username' in data:
            if Students.objects.filter(username=data['username']).exclude(pk=user.pk).exists():
                return {'error': 'Username đã tồn tại'}, status.HTTP_400_BAD_REQUEST
        
        if 'email' in data:
            if Students.objects.filter(email=data['email']).exclude(pk=user.pk).exists():
                return {'error': 'Email đã tồn tại'}, status.HTTP_400_BAD_REQUEST

        if 'password' in data:
            data['password'] = make_password(data['password'])
            serializer = StudentsSerializer(instance=user, data=data, partial=True)
        
        # Lưu thay đổi sau khi kiểm tra xong
        serializer.save()
        return serializer.data, status.HTTP_200_OK

    def put(self, request):
        response, status_code = self.update_user(request.user, request.data)
        return Response(response, status=status_code)

    def patch(self, request):
        response, status_code = self.update_user(request.user, request.data)
        return Response(response, status=status_code)
