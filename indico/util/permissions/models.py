# -*- coding: utf-8 -*-
#  Copyright (C) 2019 United Nations. All Rights Reserved.

"""Permissions db models.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

from indico.core.db import db
from indico.modules.groups.models.groups import LocalGroup
from indico.modules.users import User
from indico.util.string import format_repr


__all__ = ['Permission', 'Role']


str = unicode


class NamedMixin(object):
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True, nullable=False)
    name = db.Column(db.String(length=50), nullable=False)

    def __repr__(self):
        return format_repr(self, 'id', 'name')

    def __str__(self):
        return self.name

    @classmethod
    def get_or_create(cls, name):
        obj = cls.find_first(name=name)
        if not obj:
            obj = cls(name=name)
            db.session.add(obj)
            db.session.flush()
        return obj


class ContextMixin(object):
    main_pk = db.Column(db.Integer(), nullable=False)
    side_pk = db.Column(db.Integer())


class GeneralContextMixin(object):
    main_table = db.Column(db.String(length=100), nullable=False)
    side_table = db.Column(db.String(length=100))


user_roles = db.Table(
    'user_roles',
    db.metadata,
    db.Column(
        'user_id',
        db.Integer,
        db.ForeignKey('users.users.id'),
        nullable=True,
        index=True,
    ),
    db.Column(
        'group_id',
        db.Integer,
        db.ForeignKey('users.groups.id'),
        nullable=True,
        index=True,
    ),
    db.Column(
        'role_id',
        db.Integer,
        db.ForeignKey('permissions.roles.id'),
        nullable=False,
        index=True,
    ),

    db.Column('main_table', db.String, nullable=False, index=True),
    db.Column('side_table', db.String, nullable=True, index=True),
    db.Column('main_pk', db.Integer, nullable=False, index=True),
    db.Column('side_pk', db.Integer, nullable=True, index=True),
    db.UniqueConstraint('group_id', 'user_id', 'role_id', 'main_table', 'main_pk',
                        'side_table', 'side_pk'),
    db.CheckConstraint('(user_id is null and group_id is not null) or (user_id is not null and group_id is null)',
                       'user_or_group'),
    schema='permissions',
)


class Role(NamedMixin, db.Model):
    __tablename__ = 'roles'
    __table_args__ = ({'schema': 'permissions'},)

    id = db.Column(
        db.Integer(),
        primary_key=True,
        autoincrement=True,
        nullable=False,
    )

    permissions = db.relationship('Permission')
    users = db.relationship(
        User,
        secondary=user_roles,
    )
    groups = db.relationship(
        LocalGroup,
        secondary=user_roles,
    )

    def __str__(self):
        return self.name

    def __repr__(self):
        return format_repr(self, 'id', 'name')


class Permission(NamedMixin, db.Model):
    __tablename__ = 'permissions'
    __table_args__ = ({'schema': 'permissions'},)

    role_id = db.Column(
        db.ForeignKey(Role.id,), nullable=False
    )
