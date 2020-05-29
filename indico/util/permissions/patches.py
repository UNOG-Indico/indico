# -*- coding: utf-8 -*-
#  Copyright (C) 2019 United Nations. All Rights Reserved.

"""Permission patcher module.
This implements all the patches needed by permission handling.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import gc
from operator import isCallable, itemgetter

import flask

from indico.core import signals
from indico.util.caching import memoize_request

from . import logger


exploded_permissions = {}
patched_classes = set()
model_classes = {cls.__name__: cls for cls in gc.get_objects() if type(cls) is type and hasattr(cls, '__table__')}


def flatten_tree(node, parent=None):
    for key, value in node.items():
        yield key, parent
        if isinstance(value, dict):
            for item in flatten_tree(value, key):
                yield item


def standard_get_context(rh):
    """Default context getter
    """
    if hasattr(rh, 'permission_context'):
        return rh.permission_context
    return None


def inject_permission_in_models():
    import gc
    import itertools
    from indico.util.permissions import permission_manager
    original_permissions = set()

    def patch_method(cls, method_name):
        old_can = getattr(cls, method_name)
        if not isCallable(old_can):
            return
        permission_name = '{}.{}'.format(cls.__name__.lower(), method_name[4:]).replace('manage_', 'manage.')
        logger.info('Patching permission method %s.%s() --> %r', cls.__name__, method_name, permission_name)
        original_permissions.add(permission_name)

        @memoize_request
        def can_do(self, user, *args, **kwargs):
            name = permission_name
            subpermission = kwargs.get('permission')
            if subpermission:
                name = '{}.{}'.format(permission_name, subpermission)
            # if getattr(flask.g, 'permission_manager', None) == 'old':
            #     logger.info('Core %s could have call new permission can(%r)', name, self)
            #     return old_can(self, user, *args, **kwargs)
            logger.info('Core %s.%s call redirected to new permission can()', cls.__name__, name)
            return permission_manager.can(user, name, self)

        try:
            cls.__dict__[method_name] = can_do
        except TypeError:
            setattr(cls, method_name, can_do)

    models = (mod for mod in gc.get_objects() if isinstance(mod, type) and hasattr(mod, '__table__'))
    methods_iter = ((mod, set(x for x in dir(mod) if x.startswith('can_manage'))) for mod in models)
    for cls, methods in itertools.ifilter(itemgetter(1), methods_iter):
        for method in methods:
            patch_method(cls, method)
    return original_permissions


# patching menu items
def patch_side_menus():
    from indico.web import menu

    def sideMenuItemNew(cls, *args, **kwargs):
        if getattr(flask.g, 'permission_manager', 'old') == 'old':
            return object.__new__(cls, *args, **kwargs)
        else:
            user = flask.session.user
            if not user:
                return None
            url = kwargs.get('url') or args[3]
            if flask.g.permission_manager.is_url_accessible(user, path=url) is False:
                return None
            return object.__new__(cls, *args, **kwargs)

    menu.SideMenuItem.__new__ = classmethod(sideMenuItemNew)
    # menu.TopMenuItem.__new__ = classmethod(sideMenuItemNew)


@signals.acl.entry_changed.connect
def _log_acl_changes(sender, obj, principal, entry, is_new, old_data, quiet, **kwargs):
    from . import permission_manager
    from indico.modules.users import User
    from indico.modules.groups.models.groups import LocalGroup

    permission_maps = {
        'paper_editing': 'Paper Editor',
        'paper_manager': 'Paper Manager',
        'poster_editing': 'Poster Editor',
        'registration': 'Registrar',
        'slides_editing': 'Slides Editor',
        'submit': 'Submitter',
        'surveys': 'Surveyer',
        'create': 'Event Creator',
    }
    # print('Sender : {}\nObj: {}\nPrincipal: {}\nExtry: {}\nIs new: {}\nOld data: {}\nQuite: {}'.format(
    #         sender, obj, principal, entry, is_new, old_data, quiet))

    if not isinstance(principal, (User, LocalGroup)) or not entry:
        return

    role_name = '{} Reader'.format(obj.__class__.__name__)
    if entry.read_access and not old_data.get('read_access'):
        permission_manager.assign(principal, role_name, obj)
    elif not entry.read_access and old_data.get('read_access'):
        permission_manager.unassign(principal, role_name, obj)

    role_name = '{} Manager'.format(obj.__class__.__name__)
    if entry.full_access and not old_data.get('full_access'):
        permission_manager.assign(principal, role_name, obj)
    elif not entry.full_access and old_data.get('full_access'):
        permission_manager.unassign(principal, role_name, obj)

    for perm in set(old_data.get('permissions', ())).difference(entry.permissions):
        permission_manager.unassign(principal, permission_maps[perm], obj)

    for perm in set(entry.permissions).difference(old_data.get('permissions', ())):
        permission_manager.assign(principal, permission_maps[perm], obj)
