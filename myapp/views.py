from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated,AllowAny
from .models import Students
from .serializers import StudentsSerializer
from rest_framework_simplejwt.exceptions import TokenError,InvalidToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

class CustomJWTAuthentication(JWTAuthentication):
    def get_user(self,validated_token):
        try:
            user_id = validated_token.get('user_id')
            user = Students.objects.get(id=user_id)
            return user
        except Students.DoesNotExist:
            raise InvalidToken("User not found")
        
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self,request):
        username = request.data.get("username")
        password = request.data.get("password")

        try:
            user = Students.objects.get(username=username, password=password)
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            access_token["user_id"] = user.id
            access_token["username"] = user.username
            access_token["age"] = user.age
            access_token["address"] = user.address

            return Response({
                'id':user.id,
                'username':user.username,
                'access':str(access_token),
                'refresh':str(refresh)
            })
        except Students.DoesNotExist:
            return Response({'error':'Sai thong tin dang nhap'}, status=status.HTTP_401_UNAUTHORIZED)
        
class UserDetailView(APIView):
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
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
