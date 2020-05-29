# -*- coding: utf-8 -*-
#  Copyright (C) 2019 United Nations. All Rights Reserved.

"""Permissions IO.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os

import yaml

from . import logger


str = unicode

permissions_filename = os.sep.join(__file__.split(os.sep)[:-1] + ['permissions.yaml'])


def read_permission_settings():
    """Read the permissions file from the permissions module

    :return: permission hierarchical
    :
    """
    if os.path.exists(permissions_filename):
        logger.info('Reading permissions from %s', permissions_filename)
        with open(permissions_filename) as conf_file:
            return yaml.load(conf_file.read())
    else:
        logger.warn('No permission file found. Indico is running out of permissions')
    return {}


def save_permissions_settings(settings):
    """Store permission configuration to permissions.yaml file

    :param settings: permissions hierarchy
    :return:
    """
    logger.info('Writing permissions settings to %s', permissions_filename)
    with open(permissions_filename, 'w') as file:
        return file.write(yaml.dump(settings))
