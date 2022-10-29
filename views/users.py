from flask import request
from flask_restx import Resource, Namespace
from models import User, UserSchema
from setup_db import db

user_ns = Namespace('/users')


@user_ns.route('/')
class UserViews(Resource):
    def get(self):
        users = User.query.all()
        return UserSchema(many=True).dump(users)

    def post(self):
        user = request.json
        try:
            db.session.add(User(**user))
            db.session.commit()
            return 'User add', 201
        except Exception as e:
            db.session.rollback()
            return e, 200

@user_ns.route('/<int:uid>')
class UserViews(Resource):
    def get(self, uid):
        ...

    def put(self, uid):
        ...
