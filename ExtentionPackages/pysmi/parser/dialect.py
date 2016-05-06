#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#

#
# Preconfigured sets of parser options.
# Individual options could be used in certain combinations.
#
smiV2 = {}

smiV1 = smiV2.copy()
smiV1.update(
    supportSmiV1Keywords=True,
    supportIndex=True
)

smiV1Relaxed = smiV1.copy()
smiV1Relaxed.update(
    commaAtTheEndOfImport=True,
    commaAtTheEndOfSequence=True,
    mixOfCommasAndSpaces=True,
    uppercaseIdentifier=True,
    lowcaseIdentifier=True,
    curlyBracesAroundEnterpriseInTrap=True,
    noCells=True
)
