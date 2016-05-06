#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
from pysmi.parser.smi import parserFactory
from pysmi.parser.dialect import smiV1Relaxed

# compatibility stub
SmiV1CompatParser = parserFactory(**smiV1Relaxed)
