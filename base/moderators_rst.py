from __future__ import annotations

from flask_jwt_extended import get_jwt
from flask_restx import Resource
from flask_restx.reqparse import RequestParser

from common import sessionmaker
from ._mub_restx import MUBNamespace
from .moderators_db import Moderator, BlockedModToken, InterfaceMode

mub_base_namespace = MUBNamespace("base", sessionmaker=sessionmaker, path="")


@mub_base_namespace.route("/sign-in/")
class SignInResource(Resource):
    parser: RequestParser = RequestParser()
    parser.add_argument("username", type=str, required=True)
    parser.add_argument("password", type=str, required=True)

    @mub_base_namespace.doc_aborts(("200 ", "Moderator does not exist"), (" 200", "Wrong password"))
    @mub_base_namespace.with_optional_jwt()
    @mub_base_namespace.with_begin
    @mub_base_namespace.argument_parser(parser)
    @mub_base_namespace.marshal_with_authorization(Moderator.SelfModel, auth_name="mub")
    def post(self, session, username: str, password: str):
        moderator = Moderator.find_by_name(session, username)
        if moderator is None:
            return "Moderator does not exist"

        if Moderator.verify_hash(password, moderator.password):
            return moderator, moderator
        return "Wrong password"


@mub_base_namespace.route("/sign-out/")
class SignInResource(Resource):
    @mub_base_namespace.with_begin
    @mub_base_namespace.removes_authorization(auth_name="mub")
    def post(self, session):
        BlockedModToken.create(session, jti=get_jwt()["jti"])
        return True


@mub_base_namespace.route("/my-settings/")
class PermissionsResource(Resource):
    @mub_base_namespace.jwt_authorizer(Moderator)  # TODO pagination for permissions?
    @mub_base_namespace.marshal_with(Moderator.SelfModel)
    def get(self, moderator, **_):
        return moderator

    parser = RequestParser()
    parser.add_argument("mode", required=False)

    @mub_base_namespace.doc_abort(400, "Wrong interface mode")
    @mub_base_namespace.jwt_authorizer(Moderator, use_session=False)
    @mub_base_namespace.argument_parser(parser)
    def post(self, moderator, mode: str | None):
        if mode is not None:
            mode = InterfaceMode.from_string(mode)
            if mode is None:
                mub_base_namespace.abort(400, "Wrong interface mode")
            moderator.mode = mode
        return True
