from __future__ import annotations

from flask_restx import Resource
from flask_restx.reqparse import RequestParser

from common import RestXNamespace, counter_parser, sessionmaker
from ..base import permission_index, Moderator, Permission, ModPerm

read_mods = permission_index.add_permission("read_mods")
create_mods = permission_index.add_permission("create_mods")
manage_mods = permission_index.add_permission("manage_mods")

superuser_namespace: RestXNamespace = RestXNamespace("mub-superuser", sessionmaker=sessionmaker, path="/mub/")
permission_model = superuser_namespace.model(model=Permission.IndexModel)


@superuser_namespace.route("/permissions/")
class PermissionIndex(Resource):
    @permission_index.require_permission(superuser_namespace, manage_mods, use_moderator=False)
    @superuser_namespace.argument_parser(counter_parser)
    @superuser_namespace.lister(100, Permission.IndexModel)
    def get(self, session, start: int, finish: int):
        return Permission.search(session, start, finish - start)


@superuser_namespace.route("/moderators/")
class ModeratorIndex(Resource):
    parser = RequestParser()
    parser.add_argument("username", required=True)
    parser.add_argument("password", required=True)

    @permission_index.require_permission(superuser_namespace, read_mods, use_moderator=False)
    @superuser_namespace.argument_parser(counter_parser)
    @superuser_namespace.lister(100, Moderator.IndexModel)
    def get(self, session, start: int, finish: int):
        return Moderator.search(session, start, finish - start)

    @permission_index.require_permission(superuser_namespace, create_mods, use_moderator=False)
    @superuser_namespace.argument_parser(parser)
    def post(self, session, username: str, password: str):
        Moderator.register(session, username, password)


@superuser_namespace.route("/moderators/<int:moderator_id>/")
class ModeratorManager(Resource):
    parser = RequestParser()
    parser.add_argument("username", required=False)
    parser.add_argument("append_perms", type=int, required=False, action="append")
    parser.add_argument("remove_perms", type=int, required=False, action="append")

    @superuser_namespace.doc_abort(403, "Insufficient permissions")
    @permission_index.require_permission(superuser_namespace, manage_mods)
    @superuser_namespace.database_searcher(Moderator, result_field_name="target")
    @superuser_namespace.argument_parser(parser)
    def post(self, session, moderator: Moderator, target: Moderator, username: str | None,
             append_perms: list[int] | None, remove_perms: list[int] | None):  # TODO replace mode?
        if username is not None:
            target.username = username
            # TODO expire all current sessions

        append_perms = append_perms or []
        remove_perms = remove_perms or []
        perms = append_perms + remove_perms
        for permission_id in perms:
            if ModPerm.find_by_ids(session, moderator.id, permission_id) is None:
                superuser_namespace.abort(403, f"You can not grant or remove #{permission_id}")

        for permission_id in append_perms:
            ModPerm.create_unique(session, target.id, permission_id)
        ModPerm.bundle_delete(session, target.id, remove_perms)

    @superuser_namespace.doc_abort(400, "Target is the source")
    @permission_index.require_permission(superuser_namespace, manage_mods)
    @superuser_namespace.database_searcher(Moderator, result_field_name="target")
    def delete(self, session, moderator: Moderator, target: Moderator):
        if moderator.id == target.id:
            superuser_namespace.abort(400, "Target is the source")
        target.delete(session)
