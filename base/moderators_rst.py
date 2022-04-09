from flask import jsonify
from flask_jwt_extended import set_access_cookies, create_access_token, unset_jwt_cookies, get_jwt
from flask_restx import Resource
from flask_restx.reqparse import RequestParser

from common import RestXNamespace, counter_parser, sessionmaker
from .moderators_db import Moderator, Permission, BlockedModToken

mub_base_namespace = RestXNamespace("mub-base", sessionmaker=sessionmaker, path="/mub/")
permission_model = mub_base_namespace.model(model=Permission.IndexModel)


@mub_base_namespace.route("/sign-in/")
class SignInResource(Resource):
    parser: RequestParser = RequestParser()
    parser.add_argument("username", type=str, required=True)
    parser.add_argument("password", type=str, required=True)

    @mub_base_namespace.with_begin
    @mub_base_namespace.argument_parser(parser)
    def post(self, session, username: str, password: str):
        moderator = Moderator.find_by_name(session, username)
        if moderator is None:
            return "Moderator does not exist"

        if Moderator.verify_hash(password, moderator.password):
            response = jsonify("Success")
            set_access_cookies(response, create_access_token(identity=moderator.id))
            return response
        return "Wrong password"


@mub_base_namespace.route("/sign-out/")
class SignInResource(Resource):
    @mub_base_namespace.jwt_authorizer(Moderator, check_only=True)
    def post(self, session):
        response = jsonify(True)
        BlockedModToken.create(session, jti=get_jwt()["jti"])
        unset_jwt_cookies(response)
        return response


@mub_base_namespace.route("/permissions/")
class PermissionsResource(Resource):
    @mub_base_namespace.jwt_authorizer(Moderator)
    @mub_base_namespace.argument_parser(counter_parser)
    @mub_base_namespace.lister(100, Permission.IndexModel)
    def get(self, session, moderator, start: int, finish: int):
        if moderator.superuser:
            return Permission.search(session, start, finish - start, search)
        return moderator.find_permissions(session, start, finish - start)
