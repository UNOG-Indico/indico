# -*- coding: utf-8 -*-
#  Copyright (C) 2019 United Nations. All Rights Reserved.

"""Permissions cli commands.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

from . import logger
from .utils import application_endpoints, dict_merge


str = unicode

__all__ = []


def endpoint_permission_file(file_path=None):
    """Generates the url_permissions file according with the class declaration
    at the moment of the execution.
    If the "url_permissions.yaml" file exists already it will merge with all
    new URLs added the URL map

    :return: None
    """
    from itertools import groupby, ifilter
    from operator import itemgetter
    from indico.util.permissions.utils import read_yaml_dict, write_yaml_dict

    def make_tree(grp):
        ret = {bytes(g): make_tree((y[1:] for y in x if len(y) > 1 and y[1]))
               for g, x in groupby(ifilter(bool, grp), itemgetter(0))}
        return ret or None

    if not file_path:
        import os
        file_path = os.path.join(os.path.abspath(os.path.split(__file__)[0]), 'endpoint_permissions.yaml')

    logger.info('Updating "%s" file', file_path)

    endpoints = application_endpoints()
    stored_endpoints = read_yaml_dict(file_path)

    endpoints = dict_merge(stored_endpoints, endpoints)
    write_yaml_dict(endpoints, file_path)

    logger.info('"%s" updated', file_path)


def init_roles():
    """Creates the default BASE roles."""

    from indico.util.permissions import permission_manager
    from indico.core.db import db
    roles = {
        'Event Manager': {
            'event.manage', 'event.manage.read', 'event.manage.paper_editing',
            'event.manage.paper_manager', 'event.manage.poster_editing', 'event.manage.registration',
            'event.manage.slide_editing', 'event.manage.submit', 'event.manage.surveys',
        },
        'Event Reader': {'event.manage.read'},
        'Paper Editor': {'event.manage.paper_editing'},
        'Paper Manager': {'event.manage.paper_manager'},
        'Poster Editor': {'event.manage.poster_editing'},
        'Registrar': {'event.manage.registration'},
        'Slides Editor': {'event.manage.slide_editing'},
        'Submitter': {'event.manage.submit'},
        'Surveyer': {'event.manage.surveys'},
        'Category Manager': {'category.manage.category', 'category.manage.create', 'category.manage'},
        'Event Creator': {'category.manage.create'},
    }
    roles['Category Manager'].update(roles['Event Manager'])
    for role_name, permissions in roles.items():
        for permission in permissions:
            permission_manager.grant(role_name, permission)
    db.session.commit()
