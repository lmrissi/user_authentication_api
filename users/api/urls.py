from django.urls import path
from rest_framework import routers
from .views import AuthViewSet

app_name = 'users'

router = routers.DefaultRouter(trailing_slash=False)
router.register('api/auth', AuthViewSet, basename='auth')

urlpatterns = router.urls