from __future__ import annotations

from passlib.handlers.pbkdf2 import pbkdf2_sha256
from sqlalchemy import Column, ForeignKey, select, delete
from sqlalchemy.orm import relationship
from sqlalchemy.sql.functions import count
from sqlalchemy.sql.sqltypes import Integer, String, Boolean, Enum

from common import Base, PydanticModel, Identifiable, UserRole, TypeEnum
from .permissions_db import Permission, Section


class InterfaceMode(TypeEnum):
    DARK = 0
    LIGHT = 1


class Moderator(Base, Identifiable, UserRole):
    __tablename__ = "mub-moderators"

    @staticmethod
    def generate_hash(password) -> str:
        return pbkdf2_sha256.hash(password)

    @staticmethod
    def verify_hash(password, hashed) -> bool:
        return pbkdf2_sha256.verify(password, hashed)

    id = Column(Integer, primary_key=True)
    username = Column(String(100), nullable=False, unique=True)
    password = Column(String(100), nullable=False)
    super = Column(Boolean, nullable=False, default=False)

    mode = Column(Enum(InterfaceMode), nullable=False, default=InterfaceMode.DARK)

    permissions = relationship("ModPerm", cascade="all, delete")

    @PydanticModel.include_context("session")
    class SectionModel(PydanticModel.column_model(id)):
        sections: list[Section.FullModel]

        @classmethod
        def callback_convert(cls, callback, orm_object: Moderator, session=None, **context) -> None:
            callback(sections=[Section.FullModel.convert(
                section, permissions=orm_object.get_section_permissions(session, section))
                for section in Section.get_all(session)])

    @PydanticModel.include_context("session")
    class PermissionsModel(PydanticModel.column_model(id)):
        permissions: list[Permission.IndexModel]

        @classmethod
        def callback_convert(cls, callback, orm_object: Moderator, session=None, **context) -> None:
            callback(permissions=[Permission.IndexModel.convert(permission)
                                  for permission in orm_object.get_permissions(session)])

    BaseModel = PydanticModel.column_model(mode, username)
    IndexModel = PermissionsModel.column_model(username, super)
    SelfPermissionModel = BaseModel.combine_with(PermissionsModel)
    SelfModel = BaseModel.combine_with(SectionModel)

    @classmethod
    def register(cls, session, username: str, password: str):
        return Moderator.create(session, username=username, password=Moderator.generate_hash(password))

    @classmethod
    def find_by_id(cls, session, entry_id: int) -> Moderator | None:
        return session.get_first(select(cls).filter_by(id=entry_id))

    @classmethod
    def find_by_identity(cls, session, identity: int) -> Moderator | None:
        return cls.find_by_id(session, identity)

    @classmethod
    def find_by_name(cls, session, username: str):
        return session.get_first(select(cls).filter_by(username=username))

    @classmethod
    def search(cls, session, offset: int, limit: int, search: str | None = None,
               exclude: int = None) -> list[Moderator]:
        stmt = select(cls)
        if exclude is not None:
            stmt = stmt.filter(cls.id != exclude)
        if search is not None:
            stmt = stmt.filter(cls.username.like(f"%{search}%"))
        return session.get_paginated(stmt.order_by(cls.username), offset, limit)

    def get_permissions(self, session) -> list[Permission]:
        if self.super:
            return Permission.get_all(session)
        return session.get_all(select(Permission).join(ModPerm).filter(ModPerm.moderator_id == self.id))

    def get_section_permissions(self, session, section: Section) -> list[Permission]:
        if self.super:
            return section.permissions
        return ModPerm.find_by_mod_and_section(session, self.id, section.id)

    def check_permissions(self, session, permission_ids: list[int]) -> bool:
        stmt = select(count(ModPerm)).filter_by(moderator_id=self.id).filter(ModPerm.permission_id.in_(permission_ids))
        return session.get_first(stmt) == len(permission_ids)

    def get_identity(self):
        return self.id


class BlockedModToken(Base):  # TODO replace with full session control
    __tablename__ = "blocked-mod-tokens"

    id = Column(Integer, primary_key=True)
    jti = Column(String(36), nullable=False)


class ModPerm(Base):
    __tablename__ = "mub-modperms"

    moderator_id = Column(Integer, ForeignKey("mub-moderators.id"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("mub-permissions.id"), primary_key=True)
    permission = relationship("Permission", foreign_keys=[permission_id])

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

    @classmethod
    def find_by_mod_and_section(cls, session, moderator_id: int, section_id: int) -> list[Permission]:
        stmt = select(Permission).filter_by(section_id=section_id).join(cls).filter_by(moderator_id=moderator_id)
        return session.get_all(stmt)
