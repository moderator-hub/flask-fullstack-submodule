from dataclasses import dataclass

from common import sessionmaker
from .moderators_db import Permission


@dataclass
class PermissionInt:
    name: str


@dataclass
class PermissionIndex:
    permissions: set[str]
    permission_list: list[str] = None
    initialized: bool = False

    def add_permission(self, name: str):
        if self.initialized:
            raise RuntimeError("Dynamically adding permissions after initialization is not supported")
        self.permissions.add(name)
        return PermissionInt(name)

    @sessionmaker.with_begin
    def initialize(self, session):
        for name in self.permissions:
            if Permission.find_by_name(session, name) is None:
                Permission.create(session, name=name)
        self.permission_list = list(self.permissions)
        # TODO check if database has more permissions, than self does


permission_index: PermissionIndex = PermissionIndex(set())
