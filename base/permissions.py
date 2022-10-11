from __future__ import annotations

from dataclasses import dataclass
from functools import wraps

from flask_fullstack import get_or_pop

from common import ResourceController
from .moderators_db import Moderator, ModPerm
from .permissions_db import Section, Permission


class SectionInt(str):
    pass


class PermissionInt(str):
    pass


@dataclass
class PermissionIndex:
    sections: dict[str, set[str]] = None
    sections_dict: dict[str, id] = None
    permission_dict: dict[str, int] = None
    initialized: bool = False

    def __post_init__(self):
        self.sections = {}

    def add_section(self, name: str) -> SectionInt:
        if self.initialized:
            raise RuntimeError("Dynamically adding sections after initialization is not supported")
        if name in self.sections:
            raise KeyError(f"Section {name} is already created")
        self.sections[name] = set()
        return SectionInt(name)

    def add_permission(self, section: SectionInt, name: str) -> PermissionInt:
        if self.initialized:
            raise RuntimeError("Dynamically adding permissions after initialization is not supported")
        if section not in self.sections:
            raise KeyError(f"Section {section} is not created")
        if name in self.sections[section]:
            raise KeyError(f"Permission {section} is already created")
        self.sections[section].add(name)
        return PermissionInt(section + " " + name)

    def initialize(self):
        self.permission_dict = {}
        self.sections_dict = {}

        for section_name, permissions in self.sections.items():
            section = Section.find_by_name_or_create(section_name)
            self.sections_dict[section_name] = section.id

            for permission_name in permissions:
                permission = Permission.find_by_name_or_create(permission_name, section_id=section.id)
                self.permission_dict[section_name + " " + permission_name] = permission.id

        self.initialized = True
        # TODO check if database has more permissions, than self does

    def require_permission(self, ns: ResourceController, permission: PermissionInt,
                           use_moderator: bool = True, optional: bool = False):
        def require_permission_wrapper(function):
            @ns.doc_abort(403, "Not sufficient permissions")
            @wraps(function)
            @ns.jwt_authorizer(Moderator)
            def require_permission_inner(*args, **kwargs):
                moderator = get_or_pop(kwargs, "moderator", use_moderator)
                declined = (not moderator.super
                            and ModPerm.find_by_ids(moderator.id, self.permission_dict[permission]) is None)

                if optional:
                    kwargs["permitted"] = not declined
                elif declined:
                    ns.abort(403, "Not sufficient permissions")
                return function(*args, **kwargs)

            return require_permission_inner

        return require_permission_wrapper

    def require_permissions(self, ns: ResourceController, *permissions: PermissionInt,
                            use_moderator: bool = True, optional: bool = False):
        def require_permissions_wrapper(function):
            @ns.doc_abort(403, "Not sufficient permissions")
            @wraps(function)
            @ns.jwt_authorizer(Moderator)
            def require_permissions_inner(*args, **kwargs):
                moderator = get_or_pop(kwargs, "moderator", use_moderator)
                perms = (self.permission_dict[perm] for perm in permissions)
                permitted = moderator.super or moderator.check_permissions(list(perms))

                if optional:
                    kwargs["permitted"] = permitted
                elif not permitted:
                    ns.abort(403, "Not sufficient permissions")
                return function(*args, **kwargs)

            return require_permissions_inner

        return require_permissions_wrapper


permission_index: PermissionIndex = PermissionIndex()
