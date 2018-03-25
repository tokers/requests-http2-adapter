# -*- coding: utf-8 -*-

"""
http/2 hpack implements
~~~~~~~~~~~~~~~~~~~~~~~~
"""

from struct import pack, unpack
from .compat import range_iter
from .exceptions import HTTP2HpackEncodeError
from .exceptions import HTTP2HpackDecodeError


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

    <---------- Index Address Space ---------->
    <-- Static Table -->  <-- Dynamic Table -->
    +---+-----------+---+ +---+-----------+---+
    | 1 |     ...   | s | |s+1|     ...   |s+k|
    +---+-----------+---+ +---+-----------+---+
                          ^                   |
                          |                   V
                   Insertion Point      Dropping Point

    > The dynamic table consists of a list of header fields maintained in
    > first-in, first-out order. The first and newest entry in a dynamic table is
    > at the lowest index, and the oldest entry of a dynamic table is at the
    > highest index.

    :param dynamic: initialized dynamic table
    """
    def __init__(self, dynamic, max_dynamic_table_size):
        self.__static = hpack_static_table
        self.__dynamic = dynamic or []
        self.__dynamic_table_size = 0
        self.__max_dynamic_table_size = max_dynamic_table_size

        index = 0
        for item in self.__dynamic:
            size = len(item[0]) + len(item[1]) + 32
            self.__dynamic_table_size += size

        if self.__dynamic_table_size > self.__max_dynamic_table_size:
            raise HTTP2HpackError("initial dynamic table too large")

    def __check_dynamic_table(self, size):
        """Evicts some items properly.
        Before a new entry is added to the dynamic table, entries are evicted
        from the end of the dynamic table until the size of the dynamic table
        is less than or equal to (maximum size - new entry size) or until the
        table is empty.

        :param size: size of the new item.
        :rtype: True if the new item can be added or False otherwise.
        """
        if self.__dynamic_table_size + size < self.__max_dynamic_table_size:
            return True
        elif size > self.__max_dynamic_table_size:
            # an attempt to add an entry larger than the maximum size causes the
            # table to be emptied of all existing entries and results in an
            # empty table.
            self.__dynamic = []
            return False
        else:
            index = 0
            temp_dynamic_table_size = self.__dynamic_table_size
            for item in self.__dynamic:
                index += 1
                temp_dynamic_table_size -= len(item[0]) + len(item[1]) + 32
                if temp_dynamic_table_size + size <= self.__max_dynamic_table_size:
                    break

            self.__dynamic = self.__dynamic[index:]
            return True

    def append_header(self, header):
        """append a new entry (header) to the dynamic table.

        :param header: a tuple which represents the header.
        """
        # some types is not hashable.
        if not isinstance(header, tuple):
            raise ValueError("unexpected type \"%s\" for header" % type(header))

        size = 32 + len(header[0]) + len(header[1])
        if self.__check_dynamic_table(size) is True:
            self.__dynamic.append(header)

    def inside_index_table(self, header):
        """Judges whether the pair of header name and value is inside the hpack
        table.

        :param header: a tuple which represents the header.
        :rtype: True if this header is inside the index table or False if not.
        """
        # some types is not hashable.
        if not isinstance(header, tuple):
            raise ValueError("unexpected type \"%s\" for header" % type(header))

        return header in self.__dynamic

    def encode_indexed(self, index):
        """Indexed header field representation
          0   1   2   3   4   5   6   7
        +---+---+---+---+---+---+---+---+
        | 1 |         Index (7+)        |
        +---+---------------------------+

        :param index: index that caller want to use.
        :rtype: the encoded data stream.
        """
        if index < 1:
            raise HTTP2HpackEncodeError("invalid index")
        elif index > len(self.__static) + len(self.__dynamic):
            raise HTTP2HpackEncodeError("index out of dynamic table bound")

        index |= 1 << 7
        return pack(">B", index)

    def encode_incr_indexing(self):
        pass

    def encode_without_indexing(self):
        pass

    def encode_never_indexed(self):
        pass

    def decode(self):
        pass

    def decode_indexed(self, index):
        """Decodes the indexed header field.

        :param index: the index of static/dynamic table(start from 1)
        :rtype: a tuple which contains the corresponding header name and value.
        """
        index -= 1
        if index < len(self.__static):
            return self.__static[index]

        index -= len(self.__static)
        if index < len(self.__dynamic):
            return self.__dynamic[index]
        else:
            raise HTTP2HpackDecodeError("index out of dynamic table bound")

    def decode_incr_indexing(self):
        pass
