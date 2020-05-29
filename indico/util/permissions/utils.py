# -*- coding: utf-8 -*-
#  Copyright (C) 2019 United Nations. All Rights Reserved.

"""Permissions utils.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import marshal
from itertools import imap, starmap
from operator import attrgetter, itemgetter

import redis
import yaml

from indico.core import signals
from indico.core.db import db
from indico.modules.groups.models.groups import LocalGroup
from indico.modules.users import User
from indico.util.caching import memoize

from . import logger
from .models import Role, user_roles


str = unicode
cache = None


@signals.app_created.connect
def setup_cache(app, **kwargs):
    global cache
    from indico.core.config import config
    cache = redis.Redis.from_url(config.PERMISSION_CACHE_URL)


def cache_keys(user, table_name, id):
    """Create the redis key and name (sub-key) for object-based permission caching
    """
    return 'perm:{}'.format(user.id if user else -1), '{}-{}'.format(table_name, id)


def cache_store(user, table_name, id, permissions):
    """Stores permission bound to an `object` for a specific user"""
    key, name = cache_keys(user, table_name, id)
    cache.hset(key, name, marshal.dumps(permissions))
    cache.expire(key, 120)


def cache_get(user, table_name, id):
    """Get cached permission-set of an user stored as object level"""
    key, name = cache_keys(user, table_name, id)
    ret = cache.hget(key, name)
    if ret is not None:
        cache.expire(key, 120)
        return marshal.loads(ret)


def compress_constraints(group):
    """Compress the permission constraints if any.

    The group, coming from the itertools.groupby function is an iterator of
        (<permission name>, <table>, <id>)
    :param group: list of permissions and constraints
    :type group: (str, str, int)
    :return: set of constraints in the form (<table name>, <id>)
    :rtype: set((str, int))
    """
    ret = set()
    for _, tab, pk in group:
        if tab is None:
            return set()
        ret.add((tab, pk))
    return ret


def application_endpoints():
    """Scan all the route rules and creates the endpoint dictionary as in the
    following example:
    {'user':
        {'create': ,
        '
    """
    from indico.web.flask.app import make_app
    from itertools import groupby
    app = make_app()
    return {
        bytes(prefix): {
            bytes(ep): None
            for ep in map(lambda ep: '.'.join(ep.split('.')[1:]), suffix)
        }
        for prefix, suffix in groupby(sorted(app.url_map._rules_by_endpoint), lambda ep: ep.split('.')[0])
    }


def dict_merge(main, side):
    """It merges recursively 2 dictionaries and returns the merged dictionary
    if a key is in the main dictionary it doesn't look up for the same in the
    side dictionary.
    The key-value pair is got form the secondary dictionary only if the key
    doesn't exist in the main dictionary

    :param main: Primary dictionary
    :type main: dict
    :param side: Secondary dictionary
    :type side: dict
    :return: merged dictionary
    """
    if side:
        simple_merge = ((k, main[k] if k in main else side.get(k)) for k in set(main).union(side))
        # recursive step
        return dict(dict_merge(*x) if isinstance(x, dict) else x for x in simple_merge)
    return main


def clear_cache(role_or_group):
    """Clears user-based cache of a single user or all the users in a group or
    all the users having a specific role
    """
    if isinstance(role_or_group, Role):
        users = db.session.query(user_roles.c['user_id']).filter(
            user_roles.c['role_id'] == role_or_group.id).all()
        users = map(itemgetter(0), users)
    elif isinstance(role_or_group, LocalGroup):
        users = map(attrgetter('id'), role_or_group.members)
    elif isinstance(role_or_group, User):
        users = [role_or_group.id]
    else:
        logger.warning('Cache for %r not found', role_or_group)
        return
    for user in users:
        cache.delete('perm:{}'.format(user))


def private_group_name(user):
    """Defines a private group name for the given user"""
    return 'Private user-group-{}'.format(user.id)


def read_yaml_dict(filename):
    try:
        with open(filename) as f:
            stored_dict = yaml.load(f)
    except IOError:
        logger.error('Error reading file "%s"', filename, exc_info=True)
        stored_dict = {}
    return stored_dict


def write_yaml_dict(dct, filename):
    with open(filename, 'w') as f:
        yaml.dump(dct, f)


def set_first(query):
    return set(imap(itemgetter(0), query.all()))


class Arc(object):
    """Part of the permission Graph definition."""

    def __init__(self, from_node, to_node, via, skip=False, **options):
        """An arc is a connections between 2 nodes with options.
        :param from_node: the node from which the arc is build
        :type from_node: Node
        :param to_node: the node which the arc points to
        :type to_node: Node
        :param options:
        :type options: dict
        """

        table = from_node.model.__table__
        if via not in table.columns:
            raise ValueError('Table "{}" does not have field named "{}"'.format(
                table.name, via))
        self.field = table.columns[via]

        self.from_ = from_node
        self.to = to_node
        self.via = via
        self.skip = skip
        self.is_hierarchic = from_node == to_node
        self.options = options

        if self.is_hierarchic:
            self.from_.hierarchy = self

    def parent(self, id):
        """Returns the relational parent ID from the relation defined by the
        current arc
        """
        return db.session.query(self.field).filter(
            self.from_.model.id == id).scalar()

    def parents(self, *ids):
        """Returns the relational parent IDs from the relation defined by the
        current arc"""
        return set_first(db.session.query(self.field).filter(
            self.from_.model.id.in_(set(ids))))

    def children(self, *ids):
        """Returns the relational child IDs applying the relation defined by the
        current arc"""
        return set_first(db.session.query(self.from_.model.id).filter(
            self.field.in_(set(ids))))

    def get_join(self, query_object, forward=True):
        if forward:
            model = self.to.model
        else:
            model = self.from_.model
        return query_object.join(model, self.field == self.to.model.id)

    def __str__(self):
        return 'Arc({0.model.__name__} -> {1.model.__name__})'.format(
            self.from_, self.to)

    __repr__ = __str__


class Node(object):
    """Part of the permission Graph definition."""

    def __init__(self, model, public=False, **options):
        """A node in the graph. A node is a model wrapper and it includes
        a reference to the given `model`.
        :param model: is the model class of which this node is wrapper of
        :type model: any
        """
        self.hierarchy = None  # it can be a "hierarchical" arc.
        self.model = model
        self.public = public
        self.arcs = []
        self.back_arcs = set()
        self.to_nodes = set()
        self.options = options  # for further implementation

    def add(self, arc):
        """Add an arc to the current node.
        :type arc: Arc
        :rtype: NoneType
        """
        if arc.to not in self.to_nodes:
            self.to_nodes.add(arc.to)
            self.arcs.append(arc)
            arc.to.back_arcs.add(arc)
        else:
            logger.warning('Already registered node from %r to %r', arc.from_, arc.to)

    @property
    def all_adjacencies(self):
        return self.backward_adjacences + self.forward_adjacences

    @property
    def forward_adjacences(self):
        return [(arc, True) for arc in self.arcs]

    @property
    def backward_adjacences(self):
        return [(arc, False) for arc in self.back_arcs]

    @property
    def adjacent_nodes(self):
        return set(arc.to if forward else arc.from_ for arc, forward in self.all_adjacencies)

    def get(self, *ids):
        return set(db.session.query(self.model).filter(self.model.id.in_(ids)).all())

    def __str__(self):
        return 'Node({} [{} arcs])'.format(self.model.__name__, len(self.arcs))

    __repr__ = __str__


class Graph(object):
    """Entity-relation schema modeler."""
    def __init__(self, relations, node_options={}):
        """The entity-relation model initialization.

        :param relations: the full list of relations. Each relation is tuple of:
            (from model, to model, options dict)
        :type relations: (db.Model, db.Model, dict)
        """
        self.nodes = {}
        self.table_to_node = {}

        for from_model, to_model, via in relations:
            for model in (from_model, to_model):
                if model not in self.nodes:
                    self.nodes[model] = Node(model, **node_options.get(model, {}))
                    self.table_to_node[model.__tablename__] = self.nodes[model]
            from_node, to_node = itemgetter(from_model, to_model)(self.nodes)
            from_node.add(Arc(from_node, to_node, via))

    def bf_search(self, model, bidirect=False):
        """Breadth-first search iterator
        :param model: the model you want to start the search from
        :type model: db.Model
        :param bidirect: if True it search backward as well as forward
        :type bidirect: bool
        :return: [traversed arc, direction (True is forward, False is backward)]
            pairs iterator
        :rtype: ((Arc, bool))
        """
        not_yielded = lambda x: x[1] not in yielded and x not in stack
        yielded = set()
        node = self.nodes.get(model)
        if node:
            stack = node.all_adjacencies if bidirect else node.forward_adjacences
            while stack:
                arc, forward = stack.pop(0)
                if arc not in yielded:
                    yield arc, forward
                    yielded.add(arc)
                    node = arc.to if forward else arc.from_
                    stack.extend(filter(not_yielded, node.all_adjacencies if bidirect else node.forward_adjacences))
        else:
            logger.debug('Model %r is out of permission_manager', model)

    def _find_paths(self, from_, to, path, arc_path):
        """Find all possible paths from `from_` model to `to` model traversing
        the graph.
        :type from_: Node
        :type to: Node
        """
        def next_node(arc, forward):
            return (arc.to, arc) if forward else (arc.from_, arc)

        path.append(from_)
        adjacences = list(starmap(next_node, from_.all_adjacencies))
        for node, arc in adjacences:
            arc_path.append(arc)
            if node is to:
                yield arc_path
            if node not in path:
                for found in self._find_paths(node, to, path, arc_path):
                    yield found
            arc_path.remove(arc)

    @memoize
    def find_paths(self, from_, to, shortest=True):
        """Find all possible paths from `from` model to `to` model traversing
        the full graph following the BF-search.

        :param shortest: if True it returns the first path only
        :type shortest: bool
        :type from_: db.Model
        :type to: db.Model
        """
        paths = []
        for path in self._find_paths(self.nodes[from_], self.nodes[to], [], []):
            if shortest:
                return path
            paths.append(list(path))
        return paths

    def object_path(self, obj):
        """Driven by the permission schema, it traverses the actual DB looking
        for all the (table, id) pairs in which the permission can be stored to.

        TODO This can be GLOBALLY cached with a "table-id" key

        :returns: all (table-id) pairs in which permissions have to be checked
            against
        :rtype: (str, int) iter
        """
        if obj is not None:
            if isinstance(obj, tuple):
                ti = obj
                o_type = self.table_to_node[ti[0]].model
            else:
                ti = (obj.__tablename__, obj.id)
                o_type = type(obj)
            hist = {ti[0]: ti}
            yielded = {ti}

            if ti[1] is not None:
                yield ti
                for arc in imap(itemgetter(0), self.bf_search(o_type)):
                    ti = hist[arc.from_.model.__tablename__]
                    if arc.is_hierarchic:
                        parent = (arc.to.model.__tablename__, arc.parent(ti[1]))
                        if parent:
                            for parent in self.object_path(parent):
                                if parent not in yielded:
                                    yielded.add(parent)
                                    yield parent
                        else:
                            continue
                        ti = hist[arc.from_.model.__tablename__]
                    else:
                        ti = (arc.to.model.__tablename__, arc.parent(ti[1]))
                    if ti:
                        hist[ti[0]] = ti
                    if ti[1] is not None and not arc.skip:
                        if ti not in yielded:
                            yielded.add(ti)
                            yield ti

    def __str__(self):
        return 'Graph({} nodes)'.format(len(self.nodes))

    __repr__ = __str__
