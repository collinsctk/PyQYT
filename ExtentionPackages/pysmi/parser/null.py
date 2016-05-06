#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
from pysmi.parser.base import AbstractParser

class NullParser(AbstractParser):
    def __init__(self, startSym='mibFile', tempdir=''):
        pass

    def reset(self):
        pass

    def parse(self, data, **kwargs):
        return []
