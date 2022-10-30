from constants import algo, secret
import jwt
from flask import request, abort


def auth_required(func):
    """
    Декоратор проверки авторизации
    """
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]

        try:
            jwt.decode(token, secret, algorithms=[algo])
        except Exception as e:
            abort(401)

        return func(*args, **kwargs)

    return wrapper

def admin_required(func):
    """
        Декоратор проверки прав администратора
    """
    def wrapper(*args, **kwargs):

        if 'Authorization' not in request.headers:
            abort(401)
        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]
        role = None
        try:
            user = jwt.decode(token, secret, algorithms=[algo])
            role = user.get("role")
        except Exception as e:
            print(e)
            abort(401)
        if role != 'admin':
            abort(403)

        return func(*args, **kwargs)
    return wrapper
