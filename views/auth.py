import calendar
import datetime
import jwt
from flask import request
from flask_restx import Resource, Namespace, abort
from models import User
from setup_db import db
from constants import algo, secret, PWD_HASH_SALT, PWD_HASH_ITERATIONS

auth_ns = Namespace('/auth')

@auth_ns.route('/')
class AuthViews(Resource):
    def post(self):
        r_data = request.json
        username = r_data.get("username")
        password = r_data.get("password")

        if None in [username, password]:
            return "", 400

        user = db.session.query(User).filter(User.username == username).first()
        if user is None:
            raise abort(404)

        data = {
            "username": user.username,
            "role": user.role
        }

        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        tokens = {"access_token": access_token, "refresh_token": refresh_token}
        return tokens


    def put(self, refresh_token):
        data = jwt.decode(jwt=refresh_token, key=secret, algorithms=algo)
        username = data.get("username")
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        tokens = {"access_token": access_token, "refresh_token": refresh_token}
        return tokens

