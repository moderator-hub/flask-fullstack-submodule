from typing import Type

from __lib__.flask_fullstack import ResourceController, UserRole


class MUBController(ResourceController):
    def __init__(self, name: str, *, sessionmaker, no_prefix: bool = False, path: str = None, **kwargs):
        if no_prefix:
            super().__init__(name, path=path, sessionmaker=sessionmaker, **kwargs)
        else:
            super().__init__("mub-" + name, path="/mub/" + path.lstrip("/"), sessionmaker=sessionmaker, **kwargs)

    def jwt_authorizer(self, role: Type[UserRole], auth_name: str = "mub", *, result_field_name: str = None,
                       optional: bool = False, check_only: bool = False, use_session: bool = True):
        return super().jwt_authorizer(role, auth_name, result_field_name=result_field_name,
                                      optional=optional, check_only=check_only, use_session=use_session)
