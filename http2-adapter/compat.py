# -*- coding: utf-8 -*-

"""
http2-adapter's compat
~~~~~~~~~~~~~~~~~~~~~~
"""

import sys

_ver = sys.version_info

#: Python 2.x?
is_py2 = (_ver[0] == 2)

#: Python 3.x?
is_py3 = (_ver[0] == 3)


# for python/2.x, data type will be str, whereas for python/3.x, type is bytes
empty_unit = "" if is_py2 else b""
range_iter = xrange if is_py2 else range
unit_type = str if is_py2 else bytes
