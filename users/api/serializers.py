from django.contrib.auth import password_validation
from django.contrib.auth.models import BaseUserManager
from rest_framework.authtoken.models import Token
from rest_framework import serializers
from users.models import User

""" 
Serealizador utilizado para validar os dados de input no momento do registro do usuário 
"""
class RegistrationUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={"input_type": 'password'}, write_only=True)
    password2 = serializers.CharField(style={"input_type": 'password'}, write_only=True)
    class Meta:
        model = User
        fields = ('email', 'username', 'password', 'password2')
        extra_kwargs = {
            'password': {'write_only': True}
        }
    
    def save (self):
        user = User(
            email=self.validated_data['email'],
            username=self.validated_data['username'],
        )
        password = self.validated_data['password']
        password2 = self.validated_data['password2']
        if password != password2:
            raise serializers.ValidationError({'password': 'As senhas devem ser iguais'})
        user.set_password(password)
        user.save()
        return user

""" 
Serealizador que trata os inputs dos dados no momento do login. 
"""
class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=300, required=True)
    password = serializers.CharField(style={"input_type": 'password'}, required=True, write_only=True)

""" 
Serealizador utilizado na resposta da autenticação do usuário. 
"""
class AuthUserSerializer(serializers.ModelSerializer):

    class Meta:
         model = User
         fields = ('email', 'username')

""" 
Serealizador retornado caso nenhum outro seja informado no dicionário serializer_classes da classe AuthenticationViewSet.
"""
class EmptySerializer(serializers.Serializer):
    pass

""" 
Serealizador utilizado para tratar e validar dos dados de input da alteração de senha.
Valida se a senha do usuário está correta a partir do contexto que é passado pela view, que possui um método atrelado(ckeck_password).
Valida a nova senha utilizando o método password_validation. 
"""

class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(style={"input_type": 'password'}, required=True)
    new_password = serializers.CharField(style={"input_type": 'password'}, required=True)

    def validate_current_password(self,value):
        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError('O password atual está incorreto')
        return value

    def validate_new_password(self,value):
        password_validation.validate_password(value)
        return value