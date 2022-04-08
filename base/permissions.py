from dataclasses import dataclass
from functools import wraps

from common import sessionmaker, RestXNamespace, get_or_pop
from .moderators_db import Permission, Moderator, ModPerm


@dataclass
class PermissionInt:
    name: str


@dataclass
class PermissionIndex:
    permissions: set[str]
    permission_list: list[str] = None
    permission_dict: dict[str, Permission] = None
    initialized: bool = False

    def add_permission(self, name: str):
        if self.initialized:
            raise RuntimeError("Dynamically adding permissions after initialization is not supported")
        self.permissions.add(name)
        return PermissionInt(name)

    @sessionmaker.with_begin
    def initialize(self, session):
        self.permission_dict = {}
        for name in self.permissions:
            permission = Permission.find_by_name(session, name)
            if permission is None:
                permission = Permission.create(session, name=name)
            self.permission_dict[name] = permission
        self.permission_list = list(self.permissions)
        # TODO check if database has more permissions, than self does

    def require_permission(self, ns: RestXNamespace, permission: PermissionInt,
                           use_session: bool = True, use_moderator: bool = True):
        def require_permission_wrapper(function):
            @wraps(function)
            @ns.jwt_authorizer(Moderator)
            def require_permission_inner(*args, **kwargs):
                session = get_or_pop(kwargs, "session", use_session)
                moderator = get_or_pop(kwargs, "moderator", use_moderator)
                ModPerm.find_by_ids(session, moderator.id, self.permission_dict[permission.name])
                return function(*args, **kwargs)

            return require_permission_inner

        return require_permission_wrapper

    def require_permissions(self, ns: RestXNamespace, *permissions: PermissionInt,
                            use_session: bool = True, use_moderator: bool = True):
        def require_permissions_wrapper(function):
            @wraps(function)
            @ns.jwt_authorizer(Moderator)
            def require_permissions_inner(*args, **kwargs):
                session = get_or_pop(kwargs, "session", use_session)
                moderator = get_or_pop(kwargs, "moderator", use_moderator)
                if moderator.check_permissions(session, [self.permission_dict[perm.name] for perm in permissions]):
                    return function(*args, **kwargs)
                ns.abort(403, "Access denied")

            return require_permissions_inner

        return require_permissions_wrapper


permission_index: PermissionIndex = PermissionIndex(set())
