from django.urls import path, include
from .views import *
from rest_framework.routers import DefaultRouter

router = DefaultRouter()

urlpatterns = [
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/user/', UserDetailView.as_view(), name='user-detail'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='refresh-token'),
    path('', include(router.urls)),
]
