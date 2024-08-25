from django.urls import path,include
from . import views

urlpatterns = [
    path('api/register/user',views.RegisterView.as_view(), name='api-register-user'),
    path('api/login/',views.LoginView.as_view(), name='api-login-user'),
    path('api/user/', views.UserDetailView.as_view(), name='api-detail-user'),
    path('api/token/refresh/', views.TokenRefreshView.as_view(), name='refresh-token'),
    path('api/update/user/',views.UpdateUserView.as_view(), name='api-update-user')
]
