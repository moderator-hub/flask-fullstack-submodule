from __future__ import annotations

from passlib.handlers.pbkdf2 import pbkdf2_sha256
from sqlalchemy import Column, ForeignKey, select
from sqlalchemy.sql.sqltypes import Integer, String

from common import Base, PydanticModel, UserRole


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)

    @classmethod
    def find_by_name(cls, session, name: str) -> Permission | None:
        return session.get_first(select(cls).filter_by(name=name))

    @classmethod
    def search(cls, session, offset: int, limit: int, search: str | None = None) -> list[Permission]:
        return session.get_paginated(select(cls), offset, limit)

    @PydanticModel.include_columns(id, name)
    class IndexModel(PydanticModel):
        pass


class Moderator(Base, UserRole):
    __tablename__ = "moderators"

    @staticmethod
    def generate_hash(password) -> str:
        return pbkdf2_sha256.hash(password)

    @staticmethod
    def verify_hash(password, hashed) -> bool:
        return pbkdf2_sha256.verify(password, hashed)

    id = Column(Integer, primary_key=True)
    username = Column(String(100), nullable=False, unique=True)
    password = Column(String(100), nullable=False)

    @classmethod
    def register(cls, session, username: str, password: str):
        return Moderator.create(session, username=username, password=Moderator.generate_hash(password))

    @classmethod
    def find_by_id(cls, session, entry_id: int) -> Moderator | None:
        return session.get_first(select(cls).filter_by(id=entry_id))

    @classmethod
    def find_by_name(cls, session, username: str):
        return session.get_first(select(cls).filter_by(username=username))

    @classmethod
    def search(cls, session, offset: int, limit: int, search: str | None = None) -> list[Moderator]:
        return session.get_paginated(select(cls), offset, limit)

    def find_permissions(self, session, offset: int, limit: int) -> list[Permission]:
        stmt = select(Permission).join(ModPerm).filter(ModPerm.moderator_id == self.id)
        return session.get_paginated(stmt, offset, limit)


class BlockedModToken(Base):  # TODO replace with full session control
    __tablename__ = "blocked-mod-tokens"

    id = Column(Integer, primary_key=True)
    jti = Column(String(36), nullable=False)


class ModPerm(Base):
    __tablename__ = "modperms"

    moderator_id = Column(Integer, ForeignKey("moderators.id"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("permissions.id"), primary_key=True)

    @classmethod
    def find_by_moderator(cls, session, moderator_id: int, offset: int, limit: int) -> list[ModPerm]:
        return session.get_paginated(select(cls).filter_by(moderator_id=moderator_id), offset, limit)

    @classmethod
    def find_by_ids(cls, session, moderator_id: int, permission_id: int) -> ModPerm | None:
        return session.get_first(select(cls).filter_by(moderator_id=moderator_id, permission_id=permission_id))

    @classmethod
    def create_unique(cls, session, moderator_id: int, permission_id: int) -> ModPerm | None:
        if cls.find_by_ids(session, moderator_id, permission_id) is not None:
            return None
        return cls.create(session, moderator_id=moderator_id, permission_id=permission_id)

    @classmethod
    def delete_by_ids(cls, session, moderator_id: int, permission_id: int) -> bool:
        mod_perm = cls.find_by_ids(session, moderator_id, permission_id)
        return mod_perm is not None and mod_perm.delete(session) is None
