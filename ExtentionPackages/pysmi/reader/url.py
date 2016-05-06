#
# This file is part of pysmi software.
#
# Copyright (c) 2015-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysmi.sf.net/license.html
#
import sys
try:
    import urlparse
except ImportError:
    from urllib import parse as urlparse
from pysmi.reader.localfile import FileReader
from pysmi.reader.httpclient import HttpReader
from pysmi.reader.ftpclient import FtpReader
from pysmi import error

def getReadersFromUrls(*sourceUrls, **options):
    readers = []
    for sourceUrl in sourceUrls:
        mibSource = urlparse.urlparse(sourceUrl)
        if sys.version_info[0:2] < (2, 5):
            class ParseResult(tuple): pass
            mibSource = ParseResult(mibSource)
            for k, v in zip(('scheme', 'netloc', 'path', 'params',
                             'query', 'fragment', 'username', 'password',
                             'hostname', 'port'), mibSource + ('', '', '',None)):
                setattr(mibSource, k, v)
        if not mibSource.scheme or mibSource.scheme == 'file':
            readers.append(FileReader(mibSource.path).setOptions(**options))
        elif mibSource.scheme in ('http', 'https'):
            readers.append(HttpReader(mibSource.hostname or mibSource.netloc, mibSource.port or 80, mibSource.path, ssl=mibSource.scheme == 'https').setOptions(**options))
        elif mibSource.scheme in ('ftp', 'sftp'):
            readers.append(FtpReader(mibSource.hostname or mibSource.netloc, mibSource.path, ssl=mibSource.scheme == 'sftp', port=mibSource.port or 21, user=mibSource.username or 'anonymous', password=mibSource.password or 'anonymous@').setOptions(**options))
        else:
            raise error.PySmiError('Unsupported URL scheme %s' % sourceUrl)

    return readers
