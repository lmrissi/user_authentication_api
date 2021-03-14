from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers

"""
Função de autenticação que será utilizada nas views
"""
def get_and_authenticate_user(username, password):
    user = authenticate(username=username, password=password)
    if user is None:
        raise serializers.ValidationError("Nome de usuário ou senha inválidos. Por favor, tente novamente!")
    return user