#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
class AbstractParser(object):
    def reset(self):
        raise NotImplementedError()

    def parse(self, data, **kwargs):
        raise NotImplementedError()
