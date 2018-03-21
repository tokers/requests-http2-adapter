# -*- coding: utf-8 -*-

"""
http/2 hpack implements
~~~~~~~~~~~~~~~~~~~~~~~~
"""


# The Static Table Definition.
# See https://tools.ietf.org/html/rfc7541#appendix-A for more details.
hpack_static_table = (
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/")
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", 
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-rang", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-rang", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forward", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh",  ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticat", ""),
)


class HTTP2Hpack:
    """The HTTP/2 Hpack class

    :param dynamic: initialized dynamic table
    """
    def __init__(self, dynamic):
        self.__static = hpack_static_table
        self.__dynamic = dynamic or []

    def encode_indexed(self):
        pass

    def encode_incr_indexing(self):
        pass

    def encode_without_indexing(self):
        pass

    def encode_never_indexed(self):
        pass

    def encode(self, fmt=None):
        pass
