from __future__ import annotations

from flask_fullstack import counter_parser
from flask_restx import Resource
from flask_restx.reqparse import RequestParser

from ..base import permission_index, Moderator, Section, Permission, ModPerm, MUBController

super_section = permission_index.add_section("super")
manage_mods = permission_index.add_permission(super_section, "manage mods")

controller = MUBController("super", path="")

search_counter_parser = counter_parser.copy()
search_counter_parser.add_argument("search", required=False)


@controller.route("/sections/")
class SectionIndex(Resource):
    @permission_index.require_permission(controller, manage_mods, use_moderator=False)
    @controller.marshal_list_with(Section.SelfModel)
    def get(self):
        return Section.get_all()


@controller.route("/permissions/")
class PermissionIndex(Resource):
    @permission_index.require_permission(controller, manage_mods, use_moderator=False)
    @controller.marshal_list_with(Permission.IndexModel)
    def get(self):
        return Permission.get_all()


@controller.route("/moderators/")
class ModeratorIndex(Resource):
    @permission_index.require_permission(controller, manage_mods)
    @controller.argument_parser(search_counter_parser)
    @controller.lister(100, Moderator.IndexModel)
    def get(self, moderator: Moderator, start: int, finish: int, search: str | None = None):
        return Moderator.search(start, finish - start, search, moderator.id)

    parser = RequestParser()
    parser.add_argument("username", required=True)
    parser.add_argument("password", required=True)
    parser.add_argument("append-perms", type=int, required=False, dest="append_perms", action="append")

    @controller.doc_abort(400, "Moderator with is username already exists")
    @permission_index.require_permission(controller, manage_mods)
    @controller.argument_parser(parser)
    @controller.marshal_with(Moderator.IndexModel)
    def post(self, moderator: Moderator, username: str, password: str, append_perms: list[int]):
        append_perms = append_perms or []
        for permission_id in append_perms:
            if Permission.find_by_id(permission_id) is None:
                controller.abort(404, f"Permission {permission_id} does not exit")
            if not moderator.super and ModPerm.find_by_ids(moderator.id, permission_id) is None:
                controller.abort(403, f"You can't grant or remove permission #{permission_id}")

        if Moderator.find_by_name(username) is not None:
            controller.abort(400, "Moderator with is username already exists")
        target = Moderator.register(username, password)
        for permission_id in append_perms:
            ModPerm.create_unique(target.id, permission_id)
        return target


@controller.route("/moderators/<int:moderator_id>/")
class ModeratorManager(Resource):
    parser = RequestParser()
    parser.add_argument("username", required=False)
    parser.add_argument("password", required=False)
    parser.add_argument("append-perms", type=int, required=False, dest="append_perms", action="append")
    parser.add_argument("remove-perms", type=int, required=False, dest="remove_perms", action="append")

    @controller.doc_abort(400, "Target is the source")
    @controller.doc_abort(400, "Can't edit super's permissions")
    @controller.doc_abort(403, "Insufficient permissions")
    @controller.doc_abort(404, "Permission not found")
    @permission_index.require_permission(controller, manage_mods)
    @controller.database_searcher(Moderator, result_field_name="target")
    @controller.argument_parser(parser)
    def post(self, moderator: Moderator, target: Moderator, username: str | None, password: str | None,
             append_perms: list[int] | None, remove_perms: list[int] | None):  # TODO replace mode?
        if moderator.id == target.id:
            controller.abort(400, "Target is the source")
        if target.super:
            controller.abort(400, "Can't edit super's permissions")

        if username is not None:
            target.username = username
            # TODO expire all current sessions
        if password is not None:
            target.password = Moderator.generate_hash(password)
            # TODO expire all current sessions

        append_perms = append_perms or []
        remove_perms = remove_perms or []
        for permission_id in (append_perms + remove_perms):
            if Permission.find_by_id(permission_id) is None:
                controller.abort(404, f"Permission {permission_id} does not exit")
            if not moderator.super and ModPerm.find_by_ids(moderator.id, permission_id) is None:
                controller.abort(403, f"You can't grant or remove permission #{permission_id}")

        for permission_id in append_perms:
            ModPerm.create_unique(target.id, permission_id)
        ModPerm.bundle_delete(target.id, remove_perms)

    @controller.doc_abort(400, "Target is the source")
    @controller.doc_abort(403, "Can't delete a super via web api")
    @permission_index.require_permission(controller, manage_mods)
    @controller.database_searcher(Moderator, result_field_name="target")
    def delete(self, moderator: Moderator, target: Moderator):
        if moderator.id == target.id:
            controller.abort(400, "Target is the source")
        if target.super:
            controller.abort(403, "Can't delete a super via web api")
        target.delete()
