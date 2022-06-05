from __future__ import annotations

from flask_restx import Resource
from flask_restx.reqparse import RequestParser

from common import counter_parser, sessionmaker
from ..base import permission_index, Moderator, Permission, ModPerm, MUBNamespace

manage_mods = permission_index.add_permission("manage mods")

superuser_namespace = MUBNamespace("superuser", sessionmaker=sessionmaker, path="")
permission_model = superuser_namespace.model(model=Permission.IndexModel)

search_counter_parser = counter_parser.copy()
search_counter_parser.add_argument("search", required=False)


@superuser_namespace.route("/permissions/")
class PermissionIndex(Resource):
    @permission_index.require_permission(superuser_namespace, manage_mods, use_moderator=False)
    @superuser_namespace.marshal_list_with(Permission.IndexModel)
    def get(self, session):
        return Permission.get_all(session)


@superuser_namespace.route("/moderators/")
class ModeratorIndex(Resource):
    @permission_index.require_permission(superuser_namespace, manage_mods, use_moderator=False)
    @superuser_namespace.argument_parser(search_counter_parser)
    @superuser_namespace.lister(100, Moderator.IndexModel)
    def get(self, session, start: int, finish: int, search: str | None = None):
        return Moderator.search(session, start, finish - start, search)

    parser = RequestParser()
    parser.add_argument("username", required=True)
    parser.add_argument("password", required=True)

    @permission_index.require_permission(superuser_namespace, manage_mods, use_moderator=False)
    @superuser_namespace.argument_parser(parser)
    def post(self, session, username: str, password: str):
        Moderator.register(session, username, password)


@superuser_namespace.route("/moderators/<int:moderator_id>/")
class ModeratorManager(Resource):
    parser = RequestParser()
    parser.add_argument("username", required=False)
    parser.add_argument("password", required=False)
    parser.add_argument("append_perms", type=int, required=False, action="append")
    parser.add_argument("remove_perms", type=int, required=False, action="append")

    @superuser_namespace.doc_abort(400, "Target is the source")
    @superuser_namespace.doc_abort(400, "Can't edit superuser's permissions")
    @superuser_namespace.doc_abort(403, "Insufficient permissions")
    @superuser_namespace.doc_abort(404, "Permission not found")
    @permission_index.require_permission(superuser_namespace, manage_mods)
    @superuser_namespace.database_searcher(Moderator, result_field_name="target")
    @superuser_namespace.argument_parser(parser)
    def post(self, session, moderator: Moderator, target: Moderator, username: str | None, password: str | None,
             append_perms: list[int] | None, remove_perms: list[int] | None):  # TODO replace mode?
        if moderator.id == target.id:
            superuser_namespace.abort(400, "Target is the source")
        if target.superuser:
            superuser_namespace.abort(400, "Can't edit superuser's permissions")

        if username is not None:
            target.username = username
            # TODO expire all current sessions
        if password is not None:
            target.password = Moderator.generate_hash(password)
            # TODO expire all current sessions

        append_perms = append_perms or []
        remove_perms = remove_perms or []
        for permission_id in (append_perms + remove_perms):
            if Permission.find_by_id(session, permission_id) is None:
                superuser_namespace.abort(404, f"Permission {permission_id} does not exit")
            if ModPerm.find_by_ids(session, moderator.id, permission_id) is None:
                superuser_namespace.abort(403, f"You can't grant or remove permission #{permission_id}")

        for permission_id in append_perms:
            ModPerm.create_unique(session, target.id, permission_id)
        ModPerm.bundle_delete(session, target.id, remove_perms)

    @superuser_namespace.doc_abort(400, "Target is the source")
    @superuser_namespace.doc_abort(403, "Can't delete a superuser via web api")
    @permission_index.require_permission(superuser_namespace, manage_mods)
    @superuser_namespace.database_searcher(Moderator, result_field_name="target")
    def delete(self, session, moderator: Moderator, target: Moderator):
        if moderator.id == target.id:
            superuser_namespace.abort(400, "Target is the source")
        if target.superuser:
            superuser_namespace.abort(403, "Can't delete a superuser via web api")
        target.delete(session)
