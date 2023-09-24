from __future__ import annotations

from flask_fullstack import RequestParser
from flask_jwt_extended import get_jwt
from flask_restx import Resource

from ._mub_restx import MUBController
from .moderators_db import Moderator, BlockedModToken, InterfaceMode

controller = MUBController("base", path="")


@controller.route("/sign-in/")
class SignInResource(Resource):
    parser: RequestParser = RequestParser()
    parser.add_argument("username", type=str, required=True)
    parser.add_argument("password", type=str, required=True)

    @controller.doc_aborts(("200 ", "Moderator does not exist"), (" 200", "Wrong password"))
    @controller.with_optional_jwt()
    @controller.argument_parser(parser)
    @controller.marshal_with_authorization(Moderator.SelfModel, auth_name="mub")
    def post(self, username: str, password: str):
        moderator = Moderator.find_by_name(username)
        if moderator is None:
            return "Moderator does not exist"

        if Moderator.verify_hash(password, moderator.password):
            return moderator, moderator
        return "Wrong password"


@controller.route("/sign-out/")
class SignOutResource(Resource):
    @controller.removes_authorization(auth_name="mub")
    def post(self):
        BlockedModToken.create(jti=get_jwt()["jti"])
        return True


@controller.route("/my-settings/")
class PermissionsResource(Resource):
    @controller.jwt_authorizer(Moderator)  # TODO pagination for permissions?
    @controller.marshal_with(Moderator.SelfModel)
    def get(self, moderator, **_):
        return moderator

    parser = RequestParser()
    parser.add_argument("mode", required=False)

    @controller.doc_abort(400, "Wrong interface mode")
    @controller.jwt_authorizer(Moderator)
    @controller.argument_parser(parser)
    def post(self, moderator, mode: str | None):
        if mode is not None:
            mode = InterfaceMode.from_string(mode)
            if mode is None:
                controller.abort(400, "Wrong interface mode")
            moderator.mode = mode
        return True
