#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#

#
# Known attributes:
# name   -- actual MIB name
# alias  -- possible alternative to MIB name
# path   -- URL to MIB file
# file   -- MIB file name
# mtime  -- MIB file modification time
# oid    -- top-level OID defined in this MIB

class MibInfo(object):
    def __init__(self, **kwargs):
        for k in kwargs:
            setattr(self, k, kwargs[k])
