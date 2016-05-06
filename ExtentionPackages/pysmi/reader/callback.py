#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
import time
from pysmi.reader.base import AbstractReader
from pysmi.mibinfo import MibInfo
from pysmi import error
from pysmi import debug

class CallbackReader(AbstractReader):
    def __init__(self, cbFun, cbCtx=None):
        self._cbFun = cbFun
        self._cbCtx = cbCtx

    def __str__(self):
        return '%s{"%s"}' % (self.__class__.__name__, self._cbFun)

    def getData(self, mibname):
        debug.logger & debug.flagReader and debug.logger('calling user callback %s for MIB %s' % (self._cbFun, mibname))
        res = self._cbFun(mibname, self._cbCtx)
        if res:
            return MibInfo(path='file:///dev/stdin', file='', name=mibname, mtime=time.time()), res
        raise error.PySmiReaderFileNotFoundError(mibname=mibname, reader=self)
