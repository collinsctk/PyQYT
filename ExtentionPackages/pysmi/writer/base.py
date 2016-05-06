#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
class AbstractWriter(object):
    def setOptions(self, **kwargs):
        for k in kwargs:
            setattr(self, k, kwargs[k])
        return self

    def putData(self, mibname, data, comments=[], dryRun=False):
        raise NotImplementedError()
