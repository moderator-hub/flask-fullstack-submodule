from __future__ import annotations

from typing import Type, TypeVar

from sqlalchemy import Column, ForeignKey, select
from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import Integer, String

from common import Base, PydanticModel, Identifiable, db

t = TypeVar("t", bound="ModBase")


class LocalBase(Base, Identifiable):
    __abstract__ = True

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)

    IndexModel = PydanticModel.column_model(id=id, name=name)

    @classmethod
    def find_by_id(cls: Type[t], entity_id: int) -> t | None:
        return db.session.get_first(select(cls).filter_by(id=entity_id))

    @classmethod
    def find_by_name(cls: Type[t], name: str) -> t | None:
        return db.session.get_first(select(cls).filter_by(name=name))

    @classmethod
    def find_by_name_or_create(cls: Type[t], name: str, **kwargs) -> t:
        result: cls = cls.find_by_name(name)
        if result is None:
            result = cls.create(name=name, **kwargs)
        return result

    @classmethod
    def search(cls: Type[t], offset: int, limit: int, search: str | None = None) -> list[t]:
        stmt = select(cls) if search is None else select(cls).filter(cls.name.like(f"%{search}%"))
        return db.session.get_paginated(stmt.order_by(cls.name), offset, limit)

    @classmethod
    def get_all(cls: Type[t]) -> list[t]:
        return db.session.get_all(select(cls))


class Permission(LocalBase):
    __tablename__ = "mub-permissions"

    section = relationship("Section", back_populates="permissions")
    section_id = Column(Integer, ForeignKey("mub-sections.id"), nullable=False)

    @classmethod
    def find_by_section(cls, section_id: int) -> list[Permission]:
        return db.session.get_first(select(cls).filter_by(section_id=section_id))


class Section(LocalBase):
    __tablename__ = "mub-sections"

    permissions = relationship("Permission", back_populates="section", cascade="all, delete")

    @PydanticModel.include_context(permissions=list)
    class FullModel(LocalBase.IndexModel):
        permissions: list[Permission.IndexModel]

        @classmethod
        def callback_convert(cls, callback, orm_object: Section, permissions=None, **context) -> None:
            callback(permissions=[Permission.IndexModel.convert(perm, **context) for perm in permissions])

    class SelfModel(LocalBase.IndexModel):
        permissions: list[Permission.IndexModel]

        @classmethod
        def callback_convert(cls, callback, orm_object: Section, **context) -> None:
            callback(permissions=[Permission.IndexModel.convert(perm, **context) for perm in orm_object.permissions])
