from __future__ import annotations

from typing import Type, TypeVar

from sqlalchemy import Column, ForeignKey, select
from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import Integer, String

from common import Base, PydanticModel, Identifiable

t = TypeVar("t", bound="ModBase")


class LocalBase(Base, Identifiable):
    __abstract__ = True

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True, index=True)

    IndexModel = PydanticModel.column_model(id=id, name=name)

    @classmethod
    def find_by_id(cls: Type[t], session, entity_id: int) -> t | None:
        return session.get_first(select(cls).filter_by(id=entity_id))

    @classmethod
    def find_by_name(cls: Type[t], session, name: str) -> t | None:
        return session.get_first(select(cls).filter_by(name=name))

    @classmethod
    def search(cls: Type[t], session, offset: int, limit: int, search: str | None = None) -> list[t]:
        stmt = select(cls) if search is None else select(cls).filter(cls.name.like(f"%{search}%"))
        return session.get_paginated(stmt.order_by(cls.name), offset, limit)

    @classmethod
    def get_all(cls: Type[t], session) -> list[t]:
        return session.get_all(select(cls))


class Permission(LocalBase):
    __tablename__ = "mub-permissions"

    section = relationship("Section", back_populates="permissions")
    section_id = Column(Integer, ForeignKey("mub-sections.id"), nullable=False)

    @classmethod
    def find_by_section(cls, session, section_id: int) -> list[Permission]:
        return session.get_first(select(cls).filter_by(section_id=section_id))


class Section(LocalBase):
    __tablename__ = "mub-section"

    permissions = relationship("Permission", back_populates="section")

    class FullModel(LocalBase.IndexModel):
        permissions: list[Permission.IndexModel]

        @classmethod
        def callback_convert(cls, callback, orm_object: Section, **context) -> None:
            callback(permissions=[Permission.IndexModel.convert(perm, **context) for perm in orm_object.permissions])
