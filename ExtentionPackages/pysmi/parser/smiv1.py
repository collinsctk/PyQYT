#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
from pysmi.parser.smi import parserFactory
from pysmi.parser.dialect import smiV1

# compatibility stub
SmiV1Parser = parserFactory(**smiV1)
