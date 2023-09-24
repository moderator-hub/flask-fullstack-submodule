from typing import Type

from flask_fullstack import UserRole

from common import ResourceController
from .permissions import permission_index, PermissionInt


class MUBController(ResourceController):
    def __init__(self, name: str, *, no_prefix: bool = False, path: str = None, **kwargs):
        if no_prefix:
            super().__init__(name, path=path, **kwargs)
        elif path is None:
            super().__init__("mub-" + name, path=f"/mub/{name}/", **kwargs)
        else:
            super().__init__("mub-" + name, path="/mub/" + path.lstrip("/"), **kwargs)

    def jwt_authorizer(self, role: Type[UserRole], auth_name: str = "mub", *, result_field_name: str = None,
                       optional: bool = False, check_only: bool = False):
        return super().jwt_authorizer(role, auth_name, result_field_name=result_field_name,
                                      optional=optional, check_only=check_only)

    def require_permission(self, permission: PermissionInt, use_moderator: bool = True, optional: bool = False):
        return permission_index.require_permission(self, permission, use_moderator, optional)

    def require_permissions(self, *permissions: PermissionInt, use_moderator: bool = True, optional: bool = False):
        return permission_index.require_permissions(self, *permissions, use_moderator=use_moderator, optional=optional)
