#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
class AbstractSearcher(object):
    def fileExists(self, mibname, mtime, rebuild=False):
        raise NotImplementedError()
