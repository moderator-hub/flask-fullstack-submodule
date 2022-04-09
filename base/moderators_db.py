from __future__ import annotations

from passlib.handlers.pbkdf2 import pbkdf2_sha256
from sqlalchemy import Column, ForeignKey, select, delete
from sqlalchemy.sql.functions import count
from sqlalchemy.sql.sqltypes import Integer, String, Boolean

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
        stmt = select(cls) if search is None else select(cls).filter(cls.name.like(f"%{search}%"))
        return session.get_paginated(stmt.order_by(cls.name), offset, limit)

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
    superuser = Column(Boolean, nullable=False, default=False)

    @PydanticModel.include_columns(id, username, superuser)
    class IndexModel(PydanticModel):
        pass

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
        stmt = select(cls) if search is None else select(cls).filter(cls.username.like(f"%{search}%"))
        return session.get_paginated(stmt.order_by(cls.username), offset, limit)

    def find_permissions(self, session, offset: int, limit: int) -> list[Permission]:
        stmt = select(Permission).join(ModPerm).filter(ModPerm.moderator_id == self.id)
        return session.get_paginated(stmt, offset, limit)

    def check_permissions(self, session, permission_ids: list[int]) -> bool:
        stmt = select(count(ModPerm)).filter_by(moderator_id=self.id).filter(ModPerm.permission_id.in_(permission_ids))
        return session.get_first(stmt) == len(permission_ids)


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

    @classmethod
    def bundle_delete(cls, session, moderator_id: int, permission_ids: list[int]) -> None:
        session.execute(delete(cls).where(cls.moderator_id == moderator_id, cls.permission_id.in_(permission_ids)))
