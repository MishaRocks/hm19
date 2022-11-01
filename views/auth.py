import base64
import calendar
import datetime
import hashlib
import hmac

import jwt
from flask import request
from flask_restx import Resource, Namespace, abort
from models import User
from setup_db import db
from constants import algo, secret, PWD_HASH_SALT, PWD_HASH_ITERATIONS
from utils import get_hash

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

        pass_hash = get_hash(User.password)
        decode_hash = base64.b64decode(pass_hash)

        hash_pass = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        )
        if not hmac.compare_digest(decode_hash, hash_pass):
            abort(400)

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

