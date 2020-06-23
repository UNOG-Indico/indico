# This file is part of Indico.
# Copyright (C) 2002 - 2020 CERN
#
# Indico is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see the
# LICENSE file for more details.

from __future__ import unicode_literals

import logging

import flask

logger = logging.getLogger('indico.permission')

from .permissionmanager import PermissionManager


permission_manager = PermissionManager()

def can(action, context=None, user=None):
    return True
    if not user:
        user = flask.session.user
    return permission_manager.can(user, action, context)


def accessible_query(query, user=None):
    return query


def is_accessible(url):
    # TODO: implement logic
    return True


# exposing main permission management methods to the module
assign = permission_manager.assign
unassign = permission_manager.unassign
revoke = permission_manager.revoke
grant = permission_manager.grant
