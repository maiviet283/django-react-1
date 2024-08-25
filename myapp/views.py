from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import TokenError,InvalidToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Students
from .serializers import StudentsSerializer
from django.contrib.auth.hashers import make_password,check_password


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        age = data.get('age')
        name = data.get('name')
        address = data.get('address')

        # Kiểm tra xem username đã tồn tại chưa
        if Students.objects.filter(username=username).exists():
            return Response({'error': 'Username đã tồn tại'}, status=status.HTTP_400_BAD_REQUEST)

        # Kiểm tra xem email đã tồn tại chưa
        if Students.objects.filter(email=email).exists():
            return Response({'error': 'Email đã tồn tại'}, status=status.HTTP_400_BAD_REQUEST)

        # Tạo người dùng mới
        user = Students.objects.create(
            username=username,
            password=make_password(password),
            email=email,
            age=age,
            name=name,
            address=address
        )
        # Serialize và trả về thông tin người dùng
        serializer = StudentsSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            user = Students.objects.get(username=username)
            
            # Kiểm tra mật khẩu đã băm
            if check_password(password, user.password):
                # Tạo refresh token và access token
                refresh_token = RefreshToken.for_user(user)
                access_token = refresh_token.access_token

                access_token["id"] = user.id
                access_token["username"] = user.username

                return Response({
                    'id': user.id,
                    'username': user.username,
                    'access': str(access_token),
                    'refresh': str(refresh_token)
                })
            else:
                return Response({'error': 'Sai mật khẩu'}, status=status.HTTP_401_UNAUTHORIZED)
        
        except Students.DoesNotExist:
            return Response({'error': 'Sai tên đăng nhập hoặc mật khẩu'}, status=status.HTTP_401_UNAUTHORIZED)
        

class CustomJWTAuthentication(JWTAuthentication):
    def get_user(self,validated_token):
        try:
            user_id = validated_token.get('user_id')
            user = Students.objects.get(id=user_id)
            return user
        except Students.DoesNotExist:
            raise InvalidToken('User not found dell co')
        

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CustomJWTAuthentication]

    def get(self, request, *args, **kwargs):
        user = request.user
        serialier = StudentsSerializer(user)
        return Response(serialier.data, status=status.HTTP_200_OK)
    

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

    def put(self, request):
        user = request.user
        data = request.data

        if 'username' in data:
            if Students.objects.filter(username=data['username']).exists() and data['username'] != user.username:
                return Response({'error': 'Username đã tồn tại'}, status=status.HTTP_400_BAD_REQUEST)
            user.username = data['username']

        if 'email' in data:
            if Students.objects.filter(email=data['email']).exists() and data['email'] != user.email:
                return Response({'error': 'Email đã tồn tại'}, status=status.HTTP_400_BAD_REQUEST)
            user.email = data['email']

        if 'password' in data:
            user.password = make_password(data['password'])

        if 'name' in data:
            user.name = data['name']

        if 'age' in data:
            user.age = data['age']

        if 'address' in data:
            user.address = data['address']

        user.save()
        serializer = StudentsSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        user = request.user
        data = request.data

        if 'username' in data:
            if Students.objects.filter(username=data['username']).exists() and data['username'] != user.username:
                return Response({'error': 'Username đã tồn tại'}, status=status.HTTP_400_BAD_REQUEST)
            user.username = data['username']

        if 'email' in data:
            if Students.objects.filter(email=data['email']).exists() and data['email'] != user.email:
                return Response({'error': 'Email đã tồn tại'}, status=status.HTTP_400_BAD_REQUEST)
            user.email = data['email']

        if 'password' in data:
            user.password = make_password(data['password'])

        if 'name' in data:
            user.name = data['name']

        if 'age' in data:
            user.age = data['age']

        if 'address' in data:
            user.address = data['address']

        user.save()
        serializer = StudentsSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
