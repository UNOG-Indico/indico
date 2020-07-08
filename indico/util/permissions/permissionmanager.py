# -*- coding: utf-8 -*-
#  Copyright (C) 2019 United Nations. All Rights Reserved.

"""Implementation of the permission machinery (PermissionManager).
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import re
from functools import partial
from itertools import groupby, imap
from operator import attrgetter, itemgetter

import flask
import yaml
from sqlalchemy import and_, or_
from werkzeug.exceptions import Forbidden, NotFound

from indico.core import signals
from indico.core.db import db
from indico.modules.groups.models.groups import LocalGroup
from indico.modules.users.models.users import User
from indico.util.caching import memoize_request

from . import logger
from .models import Permission, Role, user_roles
from .utils import Graph, cache_get, cache_store, clear_cache, compress_constraints, read_yaml_dict


__all__ = ['PermissionManager']


class PermissionManager(object):
    """The Indico Permission Engine.
    """

    _table_class = {}

    def __init__(self, schema_file=None, endpoints_file=None,
                 db_read_permission_prefix='read', db_write_permission_prefix='write'):

        """Initialize the Indico Permission Engine.

        Indico permission manager is a graph-driven permission checking mechanism.
        Given a graph in which every node is a model and every arc is a relation,
        this object is able to:
         - check permission for application-defined URLs
         - check permission for contexts
         - transform every query in permission-driven query which limits the
         results given by the query according with the user permissions

        :param schema_file: permission file full path.
            The permission file shall be a yaml formatted file that defines the
            permission schema used by the instance of Indico.
        :type schema_file: str
        :param endpoints_file: endpoint-diven permission file
            The permission file shall be a yaml formatted file that defines
            required permissions and context per endpoint
        :type endpoints_file: str
        :param db_read_permission: name of requred permission for data reading
        :type db_read_permission: str
        :param db_write_permission: name of required permission for data writing
        :type db_write_permission: str
        """
        self._read_perm = db_read_permission_prefix + '-'
        self._write_perm = db_write_permission_prefix + '-'

        if schema_file is None:
            # from indico.core.config import config
            # schema_file = config.data.get('schema_file')
            if not schema_file:
                current_module_dir, _ = os.path.split(__file__)
                schema_file = '{}/permission_schema.yaml'.format(current_module_dir)

        if endpoints_file is None:
            endpoints_file = '{}/endpoint_permissions.yaml'.format(os.path.split(__file__)[0])

        self._schema_file_name = schema_file
        self._endpoint_file_name = endpoints_file

        signals.app_created.connect(self._deferred_init)
        self._graph = self._graph = Graph([])

    def _deferred_init(self, app, **kwargs):
        """Init deferred until the application load."""

        # TODO remove the following lines once the PMS is accepted to the core
        from .patches import patch_side_menus
        patch_side_menus()

        def flat_class_list(schema_dict):
            """Create the flat list of all the classes."""
            from itertools import chain
            return set(chain.from_iterable(zip(
                schema_dict.keys(),
                chain.from_iterable(map(dict.keys, schema_dict.values())))))

        # getting all models
        self._table_class = {cls.__tablename__: cls for cls in db.Model._decl_class_registry.values()
                             if hasattr(cls, '__tablename__')}

        model_names = {cls.__name__: cls for cls in self._table_class.values()}
        model_names.update(self._table_class)

        # reading the schema config file
        with open(self._schema_file_name) as f:
            schema_dict = yaml.load(f)

        # validating and fixing file content
        logger.debug('permission schema file validation')
        all_permission_classes = flat_class_list(schema_dict)
        node_options = {}
        unknown_classes = all_permission_classes.difference(model_names)
        if unknown_classes:
            logger.error(
                'Permission file "%s" contains the following unknown classes: %s',
                self._schema_file_name, ', '.join(map(str, unknown_classes)))
            logger.debug('Removing unknown classes from the schema')
            for class_name in unknown_classes:
                schema_dict.pop(class_name, None)
            for class_name, sub_dict in tuple(schema_dict.items()):
                options = sub_dict.pop('options', None)
                if options:
                    node_options[model_names[class_name]] = options
                for class_name in unknown_classes.intersection(sub_dict):
                    sub_dict.pop(class_name, None)

        # building the schema
        logger.debug('building the full permission schema with options')
        relations = tuple((model_names[from_], model_names[to], via)
                          for from_, x in schema_dict.items()
                          for to, via in x.items())

        self._graph = Graph(relations, node_options)

        # creating DB table -> class translator
        logger.debug('generating table to class dict')
        self._table_class = {cls.__tablename__: cls for cls in db.Model._decl_class_registry.values()
                             if hasattr(cls, '__tablename__')}

        # url-based permissions
        endpoints_conf = read_yaml_dict(self._endpoint_file_name)

        self._endpoints = {}
        for prefix, x in endpoints_conf.items():
            for suffix, options in x.items():
                if options:
                    self._endpoints['{}.{}'.format(prefix, suffix)] = options

        User.roles = property(self.get_roles_dict)
        from .patches import inject_permission_in_models
        self.original_permissions = inject_permission_in_models()

    def session_add(self, obj, user):
        """Intercept the SQLAlchemy session.add and limits it to what the
        currently logged-in user can write into the database according with the
        `write` permission
        :param obj: sql alchemy model instance you want to save to the DB
        :type obj: any
        :param user: user performing the action (currently logged-in user)
        :type user: User
        """
        if self.can(user, self.write_perm + obj.__tablename__, obj):
            db.session.add(obj)
        else:
            logger.warning('%s tries to store object without permissions %s', user, obj)

    # URL related checking
    @staticmethod
    def _get_endpoint(url):
        """Resolve an URL to an application-defined endpoint.
        :param url: the URL you want to resolve
        :type url: str
        """
        url = '|' + url
        url = url.split('?')[0]
        if not url.endswith('/'):
            url += '/'
        for rule in flask.current_app.url_map._rules:
            m = rule.match(url)
            if m:
                return rule.endpoint, m
        url = url[:-1]
        for rule in flask.current_app.url_map._rules:
            m = rule.match(url)
            if m:
                return rule.endpoint, m

    def _get_context(self, definition, values):
        """Find an endpoint context by parsing the definition

        :param definition:
        :type definition:
        :param values:
        :type values:
        :return:
        :rtype:
        """
        try:
            if definition == 'global':
                return 'global'
            if ',' in definition:
                for d in re.split(r'\s*,\s*', definition):
                    context = self._get_context(d, values)
                    if context:
                        return context
            ctx = definition.split(';')
            table_name = ctx.pop(0)
            key = ctx.pop(0)
            return self._table_class[table_name].get(values[key])
        except Exception:
            logger.debug('Context not found for "%s" with %r', definition, values, exc_info=True)

    def _check(self, user, options, values):
        context = self._get_context(options['context'], values)
        if context:
            return self.can(user, options['requires'], context)
        raise NotFound('Context not found')

    def check_access(self):
        options = self._endpoints.get(flask.request.endpoint)
        if isinstance(options, dict):
            is_check = self._check(flask.session.user, options, flask.request.view_args)
            if is_check is False:
                raise Forbidden('Sorry, you have insufficient right to reach out this page')
            return is_check
        logger.info('Endpoint %s is not managed by PermissionManager', flask.request.endpoint)

    def is_url_accessible(self, user, path=None, endpoint=None):
        """Check if the given url is accessible to the given `user`.
        If no user is defined, it consider the currently logged-in user.
        :param user: User requesting the permission for
        :type user: User
        :param path: URL you want to check against
        :type path: str
        :param endpoint: endpoint you want to check against
        :type endpoint: str
        :return: True if the URL or endpoint is accessible
        :rtype: bool
        """
        # TODO Implement the case in which user is not defined (currently logged-in user)
        if not endpoint:
            endpoint = self._get_endpoint(path)
        if endpoint:
            endpoint, values = endpoint
            permission_options = self._endpoints.get(endpoint)
            if permission_options:
                return self._check(user, permission_options, values)

        logger.debug('No permission found for %s', endpoint)

    @staticmethod
    def grant(role, permission):
        """Grant a named-permission to a specific role or group within a given
        `context`.

        :param permission: Permission name to grant
        :type permission: str
        :param role_or_group: Role or Group
        :type role_or_group: Role|Group|User
        :param context: Context to grant the permission within
        :type context: any
        """
        perm = None
        logger.debug('Granting permission "%s" to "%s"', permission, role)
        if isinstance(role, (str, unicode)):
            role = Role.get_or_create(name=role)
        if Permission.find_first(name=permission, role_id=role.id):
            logger.info('Permission "%s" already granted to "%s"', permission, role.name)
            return
        perm = Permission(name=permission, role_id=role.id)

        clear_cache(role)
        if perm:
            db.session.add(perm)
            db.session.flush()
        else:
            raise TypeError('Cannot grant "%s" to %r' % (permission, role))

    def revoke(self, role, permission):
        """Revoke a named-permission to the given role.
        :param permission: named-permission you want to revoke
        :type permission: str
        :param role: The role you want to revoke the permission from
        :type role: Role|str|unicode
        :param context: the main context you want to revoke permission from
        :type context: ANY
        """
        logger.info('Revoking permission "%s" from "%s"', permission, role)
        if isinstance(role, (str, unicode)):
            role = Role.find_first(name=role)
            if not role:
                return
        Permission.query.filter(Permission.role_id == role.id, Permission.name == permission).delete()
        clear_cache(role)

    @staticmethod
    def assign(user_or_group, role, context, bound_to=None):
        """Assign a `User` or a `Group to a specific role with context
        A context can have a constraint (`bound_to`).
        If there is a constraint is defined, the permission is propagated only
        to objects with a relation to the bound object.

        NB: For global roles such as admin-like roles use "global"

        :param user_or_group: the user or the group who you want to assign a role
        :type user_or_group: User|LocalGroup
        :param role: the role you want to assign the user to
        :type role: Role|str|unicode
        :param context: is the context you want to assign the role to the user
        :type context: ANY
        """
        # input validation
        if not isinstance(user_or_group, (User, LocalGroup)):
            raise TypeError('Users instance only can be assigned to membership')
        if isinstance(role, (str, unicode)):
            role = Role.get_or_create(role)
        if not isinstance(role, Role):
            raise TypeError('role argument can only be a Role instance or a string')
        if context is None:
            raise ValueError('When you assign a user to a role, you must give a context')
        if context == 'global':
            context = None
        if isinstance(context, (str, unicode)):
            raise TypeError('Permission `context` must be a model instance. %r is not!' % context)
        logger.info('Assignig membership ("%s", "%s") context: %s', user_or_group, role, context)

        values = dict(role_id=role.id)
        if isinstance(user_or_group, User):
            values['user_id'] = user_or_group.id
            user_name = user_or_group.full_name
        else:
            values['group_id'] = user_or_group.id
            user_name = user_or_group.name
        if context is not None:
            values.update(dict(main_table=context.__tablename__, main_pk=context.id))
        else:
            values.update(dict(main_table='global', main_pk=0))
        if bound_to:
            values.update(dict(side_table=bound_to.__tablename__, side_pk=bound_to.id))
        condition = and_(*{user_roles.c[k] == v for k, v in values.iteritems()})
        print(values)
        if not db.session.execute(user_roles.select().where(condition)).fetchall():
            db.session.execute(user_roles.insert().values(**values))
        else:
            logger.info('Role %s is already assigned to %s on %s(%s)', role, user_name,
                        context.__class__.__name__ if context else 'global',
                        context.id if context else '')
        if isinstance(user_or_group, User):
            clear_cache(user_or_group)
        else:
            for user in user_or_group.members:
                clear_cache(user)
        db.session.flush()

    @staticmethod
    def unassign(user_or_group, role, context, bound_to=None):
        """Unassign the role from the user or group within the given `context`.

        NB: For global roles such as admin-like roles use "global"

        :param user_or_group: the user you want to unassign
        :type user_or_group: User|LocalGroup
        :param role: the `role`
        :type role: Role|str|unicode
        :param context: the context you want to unassign the user from
        :type context: ANY
        """
        if isinstance(role, (str, unicode)):
            role = Role.find_first(name=role)
            if not role:
                return
        if not isinstance(user_or_group, (User, LocalGroup)):
            raise TypeError('User or Group instances only can be assigned to membership')
        if not isinstance(role, Role):
            raise TypeError('role argument can only be a Role instance')
        if context is None:
            raise ValueError('When you assign a user to a role, you must give a context')
        if context == 'global':
            context = None
        if isinstance(context, str):
            raise TypeError('Permission `context` must be a model instance. %r is not!' % context)
        if isinstance(user_or_group, User):
            user_name = user_or_group.full_name
            conditions = [user_roles.c['user_id'] == user_or_group.id]
        else:
            user_name = user_or_group.name
            conditions = [user_roles.c['group_id'] == user_or_group.id]
        logger.info('Removing the assignment %r from %s on %r', user_name, role, context)
        conditions.extend([
            user_roles.c['main_table'] == context.__tablename__ if context else None,
            user_roles.c['main_pk'] == context.id if context else None,
            user_roles.c['role_id'] == role.id,
        ])
        if bound_to:
            conditions.extend([
                user_roles.c['main_table'] == context.__tablename__,
                user_roles.c['main_pk'] == context.id
            ])
        db.session.execute(user_roles.delete().where(and_(*conditions)))
        clear_cache(user_or_group)

    # Permission checking
    def _group_filter(self, user):
        """User and group query helper.
        Checks if a user is member of groups, and returns a condition accordingly
        with the user memberships
        :param user: User
        :type user: User
        :return: user or group in SQLAlchemy condition
        :rtype: sqlalchemy.sql.elements.BinaryExpression
        """
        group_ids = map(attrgetter('id'), user.local_groups)
        if group_ids:
            user_filter = or_(
                user_roles.c['user_id'] == user.id,
                user_roles.c['group_id'].in_(group_ids)
            )
        else:
            user_filter = user_roles.c['user_id'] == user.id
        return user_filter

    def get_stored_permission(self, user, obj):
        """Get all named-permissions assigned to a user and stored onto the
        specified object regarding the given context (if any).

        :param user: The user you want to get permission of
        :type user: User
        :param obj: The DB model instance you want to check permission stored on.
        :type obj: any
        :param on: is permission context you ar going to request permission for
        :return: the full list of permission assigned to it
        :rtype: {str}
        """
        if obj is None:
            table_name, id = 'global', 0
        elif isinstance(obj, tuple) and len(obj) == 2:
            table_name, id = obj
        else:
            table_name, id = obj.__tablename__, obj.id
        ret = cache_get(user, table_name, id)
        if ret is not None:
            return ret
        query = (db.session.query(Permission.name, user_roles.c['side_table'], user_roles.c['side_pk'])
                 .join(user_roles, user_roles.c['role_id'] == Permission.role_id)
                 # .join(Role, Permission.role_id == Role.id)
                 .filter(
                     self._group_filter(user),
                     user_roles.c['main_pk'] == id,
                     user_roles.c['main_table'] == table_name))
        ret = {perm: compress_constraints(g) for perm, g in groupby(sorted(query.all()), itemgetter(0))}
        cache_store(user, table_name, id, ret)
        return ret

    def get_permissions(self, user, obj):
        """Execute the get_stored_permission method following the permission
        schema path up.
        """
        ret = {}
        for obj in self._graph.object_path(obj):
            ret.update(self.get_stored_permission(user, obj))
        return ret

    def get_read_permission_ids(self, user, model):
        """Query the DB for all the IDs which the given `user` has direct read
        permission on specified `model`
        :param user: the User
        :type user: User
        :param model: the Model class you want to get the IDs from
        :type model: db.Model
        :return: the ID of for which the specified user have read access to
        :rtype: {int}
        """
        if isinstance(model, str):
            model = self._table_class[model]
        tab_name = model.__tablename__

        query = (db.session.query(user_roles.c['main_pk'])
                 .join(Role)
                 .join(Permission)
                 .filter(
                     Permission.name == self._read_perm,
                     user_roles.c['main_table'] == tab_name,
                     user_roles.c['user_id'] == user.id))

        return set(imap(itemgetter(0), query.all()))

    # TODO REDIS cache this
    def _get_with_permission(self, user, permission):
        """Search for all the objects accessible by the user
        and returns all the table with all the id in which the `user` has the
        readable permission granted.
        :return: a dictionary in which keys are model classes and values are set
            of ID for which the `user` has read access
        :rtype: {db.Model: {int}}
        """
        if permission is None:
            permission = self._read_perm

        query = (db.session.query(user_roles.c['main_table'], user_roles.c['main_pk'],
                                  user_roles.c['side_table'], user_roles.c['side_pk'])
                 .join(Permission, user_roles.c['role_id'] == Permission.role_id)
                 .filter(
                     Permission.name.in_(self._explode_permissions(permission)),
                     self._group_filter(user)))
        print(query.debug_render())
        ret = {
            tab: {
                id: compress_constraints(g)
                for id, g in groupby(map(itemgetter(1, 2, 3), grp), itemgetter(0))
            }
            for tab, grp in groupby(sorted(query.all()), itemgetter(0))
        }
        if 'global' in ret:
            return {'global': {0}}
        # integrating result with child nodes in for hierarchies
        for model, ids in ret.items():
            arc = self._graph.nodes[self._table_class[model]].hierarchy
            if arc:
                children = ids.keys()
                while children:
                    ids.update(children)
                    children = arc.children(*children)
                ret[model] = ids
        return ret

    def accessible_query(self, user, query):
        """Generates an accessible query, based on the provided query.
        It adds filters to the original query according with the `user` granted
        read permissions.
        :param user: the User performing the query
        :type user: User
        :param query: the original query
        :type query: flask_sqlalchemy.BaseQuery
        :param read_permission: permission for which the query shall be limited
            by. By default is the basic `read_perm` defined by the `__init__`.
        :type read_permission: str
        :return: the newly generated query
        :rtype: IndicoBaseQuery
        """
        # function disabled because it's under hard development
        # def get_readable(model):
        #     perm_name = self._read_perm + model.__tablename__
        #     readables = self._get_with_permission(user, perm_name)
        #     if 'global' in readables:
        #         return readables
        #     return {self._table_class[name]: ids for name, ids in readables.iteritems()}
        #
        # # getting requested models from query
        # models = {self._table_class[c.table.name] for c in query.columns}
        #
        # # exclude public models (doesn't require restrictions)
        # models = [model for model in models if not self._graph.nodes[model].public]
        #
        # # if nothing requires restrictions, return the original
        # if not models:
        #     return query
        #
        # if len(models) > 1:
        #     logger.warning('Generating accessible permission for multiple models')
        #
        # # getting readable record-list
        # readables = {model: get_readable(model) for model in models}
        # if all('global' in val for val in readables.itervalues()):
        #     return query
        # # if the user have access to none
        # if not any(readables.values()):
        #     # return query.filter(False)
        #     return models[0].query.filter(False)
        #
        # # model-scan initialization
        # visited = {self._graph.nodes[model] for model in models}
        #
        # for model, readable in readables.items():
        #     for rm in readable:
        #         # TODO Join order should be found via a more consistent way
        #         for arc in reversed(self._graph.find_paths(rm, model)):
        #             if arc.to not in visited:
        #                 visited.add(arc.to)
        #                 # TODO it may require to remove join to already present
        #                 #  tables
        #                 query = arc.get_join(query)
        #
        #     # finalize the query with the permission union
        #     query = query.filter(or_(*(
        #         mod.id.in_(ids) for mod, ids in readable.items()
        #     )))
        # # Applying this-level iteration, SQLAlchemy::filter method makes
        # # implicitly the permission intersection (AND)
        return query

    def _check_constraint(self, context, constraint):
        """Performs a permission check over constraints.
        """
        table, pk = constraint
        arcs = self._graph.find_paths(from_=context.__class__, to=self._table_class[table])
        forward = isinstance(context, arcs[0].from_.model)
        if forward:
            ctx = context
            arc = arcs[0]
            for arc in arcs[:-1]:
                ctx = arc.to.get(getattr(ctx, arc.via))
            return pk == getattr(ctx, arc.via)
        else:
            # TODO: Implement case for permission look up
            return False

    def _check_expression(self, user, action, context):
        """Checks permissions against a binary expression in sequential notation.

        it calls `can` for each part of the expression
        """
        expr = re.split(r'\s*(\||&)\s*', action)
        act = self.can(user, expr.pop(), context)
        while expr:
            if expr:
                op = expr.pop()
            if expr and op == '|':
                if act:
                    return True
                act = self.can(user, expr.pop(), context)
            elif expr and op == '&':
                if not act:
                    return False
                act = self.can(user, expr.pop(), context)
        return act

    def _explode_permissions(self, action):
        """Explode a permission and return a set of possible star permissions.

        :param action: permission you want to explode
        :type action: str
        :return: a set of all possible permission matching
        :rtype: {str}
        """
        actions = action.split('.')
        actions = {'.'.join(actions[:x] + ['*']) for x in xrange(len(actions))}
        actions.add(action)
        return actions

    @memoize_request
    def can(self, user, action, context):
        """Check if `user` can perform `action` within the given `context`.
        :param user: The User performing the action
        :type user: User
        :param action: permission name
        :type action: str
        :param context: context in which the action is performed
        :type context: any
        """
        assert context is not None, 'You need a context to check permission against'
        if user is None:
            return False
        if '|' in action or '&' in action:
            return self._check_expression(user, action, context)
        print('check %s for %s on %r' % (user.full_name, action, context))
        actions = self._explode_permissions(action)
        permissions = self.get_stored_permission(user, None)
        ret = bool(actions.intersection(permissions))
        if ret or context == 'global':
            return ret
        for obj in reversed(tuple(self._graph.object_path(context))):
            permissions.update(self.get_stored_permission(user, obj))
            if actions.intersection(permissions):
                for act in sorted(actions, key=len, reverse=True):
                    constraints = permissions.get(act)
                    if constraints is not None:
                        if not constraints or any(imap(partial(self._check_constraint, context), constraints)):
                            return True
        return False

    def get_roles_dict(self, user):
        """Get all the roles granted to a user with the context.

        Build a dictionary where keys are role names and values is a set of
        model instances of any type for which the user has granted the role
        indicated by the corrisipoind key
        :param user: user you want to get role from
        :type user: User
        :return: roles dictionary
        :rtype: {str: {ANY}}
        """
        fields = itemgetter('role_id', 'main_table', 'main_pk')(user_roles.c)
        global_roles = []
        result = sorted(db.session.query(*fields).filter(self._group_filter(user)).all())
        for n, role in enumerate(result):
            if role[1] == 'global':
                global_roles.append(result.pop(n))
        ret = {Role.get(role_id).name: {self._table_class[tab].get(id)
               for _, tab, id in group} for role_id, group in groupby(result, itemgetter(0))}
        ret.update({Role.get(role_id).name: 'global' for role_id, tab, id in global_roles})
        return ret

    def get_roles_at(self, user, context, inherited=True, group_ids=None):
        """Look for all the roles the specified user has on a specific context.

        With the `inherited` option, the method returns, accordingly with the
        permission propagation setup, all the roles assigned to a specific context

        :param user: the User you want to get roles of
        :type user: User
        :param context: the context you want to check the permission against
        :type context: db.Model
        :param inherited: If true it traverse the permission inheritance graph
        and gather all the roles together.
        If False the method checks for roles to actual context only
        :type inherited: bool
        :param group_ids: the list of LocalGroup IDs (automatically inferred by the user)
        :type group_ids: [int]
        :return: the full set of permission, the user passed as granted to the
        actual context
        :rtype: {str}
        """
        # TODO To be cached by <user id>-<table>-<id>
        if isinstance(context, tuple):
            table, pk = context
        else:
            table, pk = context.__tablename__, context.id
        if group_ids is None:
            group_ids = map(attrgetter('id'), user.local_groups)
        if not inherited:
            return set(imap(itemgetter(0), (db.session.query(Role.name).join(user_roles).filter(
                or_(user_roles.c['user_id'] == user.id,
                    user_roles.c['group_id'].in_(group_ids)),
                user_roles.c['main_table'] == table,
                user_roles.c['main_pk'] == pk)
            ).all()))
        else:
            return reduce(set.union,
                          imap(partial(self.get_roles_at, user, inherited=False, group_ids=group_ids),
                               tuple(self._graph.object_path(context)) + (('global', 0),)),
                          set())

