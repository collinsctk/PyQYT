#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
class AbstractCodeGen(object):
    def genCode(self, ast, symbolTable, **kwargs):
        raise NotImplementedError()

    def genIndex(self, mibsMap, **kwargs):
        raise NotImplementedError()
