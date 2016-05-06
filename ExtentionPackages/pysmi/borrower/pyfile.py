#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
import imp
from pysmi.borrower.base import AbstractBorrower

class PyFileBorrower(AbstractBorrower):
    """Transformed MIB modules borrower.
    """
    for sfx, mode, typ in imp.get_suffixes():
        if typ == imp.PY_SOURCE:
            exts = [sfx]
            break
