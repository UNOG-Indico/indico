# This file is part of Indico.
# Copyright (C) 2002 - 2020 CERN
#
# Indico is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see the
# LICENSE file for more details.

from __future__ import unicode_literals

from sqlalchemy.orm import Query


def can(action, context=None, user=None):
    # TODO: implement logic
    return True


def accessible_query(query, user=None):
    # TODO: implement logic
    return Query()


def is_accessible(url):
    # TODO: implement logic
    return True
