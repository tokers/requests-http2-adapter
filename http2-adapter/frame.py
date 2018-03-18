# -*- coding: utf-8 -*-

"""
http/2 protocol frames implements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module implements all the frames defined in HTTP/2 protocol.
"""

from .compat import is_py2, is_py3, empty_object
from .exceptions import HTTP2FrameError

from array import array
from struct import pack, unpack
from urllib3.exceptions import HTTPError as _HTTPError

# error codes
HTTP_V2_NO_ERROR            = 0x0
HTTP_V2_PROTOCOL            = 0x1
HTTP_V2_INTERNAL_ERROR      = 0x2
HTTP_V2_FLOW_CTRL_ERROR     = 0x3
HTTP_V2_SETTINGS_TIMEOUT    = 0x4
HTTP_V2_STREAM_CLOSED       = 0x5
HTTP_V2_SIZE_ERROR          = 0x6
HTTP_V2_REFUSED_STREAM      = 0x7
HTTP_V2_CANCEL              = 0x8
HTTP_V2_COMP_ERROR          = 0x9
HTTP_V2_CONNECT_ERROR       = 0xa
HTTP_V2_ENHANCE_YOUR_CALM   = 0xb
HTTP_V2_INADEQUATE_SECURITY = 0xc
HTTP_V2_HTTP_1_1_REQUIRED   = 0xd

HTTP_V2_SETTINGS_ACK_SIZE   = 0
HTTP_V2_RST_STREAM_SIZE     = 4
HTTP_V2_PRIORITY_SIZE       = 5
HTTP_V2_PING_SIZE           = 8
HTTP_V2_GOAWAY_SIZE         = 8
HTTP_V2_WINDOW_UPDATE_SIZE  = 4
HTTP_V2_STREAM_ID_SIZE      = 4
HTTP_V2_SETTINGS_PARAM_SIZE = 6

HTTP_V2_HEADER_TABLE_SIZE_SETTING = 0x1
HTTP_V2_MAX_STREAMS_SETTING       = 0x3
HTTP_V2_INIT_WINDOW_SIZE_SETTING  = 0x4
HTTP_V2_MAX_FRAME_SIZE_SETTING    = 0x5

HTTP_V2_FRAME_BUFFER_SIZE = 24

HTTP_V2_DEFAULT_FRAME_SIZE = 1 << 14

HTTP_V2_FRAME_HEADER_SIZE = 9

# frame types
HTTP_V2_DATA_FRAME          = 0x0
HTTP_V2_HEADERS_FRAME       = 0x1
HTTP_V2_PRIORITY_FRAME      = 0x2
HTTP_V2_RST_STREAM_FRAME    = 0x3
HTTP_V2_SETTINGS_FRAME      = 0x4
HTTP_V2_PUSH_PROMISE_FRAME  = 0x5
HTTP_V2_PING_FRAME          = 0x6
HTTP_V2_GOAWAY_FRAME        = 0x7
HTTP_V2_WINDOW_UPDATE_FRAME = 0x8
HTTP_V2_CONTINUATION_FRAME  = 0x9

# frame flags
HTTP_V2_NO_FLAG          = 0x00
HTTP_V2_ACK_FLAG         = 0x01
HTTP_V2_END_STREAM_FLAG  = 0x01
HTTP_V2_END_HEADERS_FLAG = 0x04
HTTP_V2_PADDED_FLAG      = 0x08
HTTP_V2_PRIORITY_FLAG    = 0x20

HTTP_V2_STREAM_ID_MASK = 0x7fffffff

HTTP_V2_MAX_FRAME_SIZE = (1 << 24) - 1

HTTP_V2_MAX_WINDOW     = (1 << 31) - 1
HTTP_V2_DEFAULT_WINDOW = 65535

HTTP_V2_FRAME_TYPE_NAME = {
    HTTP_V2_DATA_FRAME: "DATA",
    HTTP_V2_HEADERS_FRAME: "HEADERS",
    HTTP_V2_PRIORITY_FRAME: "PRIORITY",
    HTTP_V2_RST_STREAM_FRAME: "RST_STREAM",
    HTTP_V2_SETTINGS_FRAME: "SETTINGS",
    HTTP_V2_PUSH_PROMISE_FRAME: "PUSH_PROMISE",
    HTTP_V2_PING_FRAME: "PING",
    HTTP_V2_GOAWAY_FRAME: "GOAWAY",
    HTTP_V2_WINDOW_UPDATE_FRAME: "WINDOW_UPDATE",
    HTTP_V2_CONTINUATION_FRAME: "CONTINUATION",
}

HTTP_V2_FRAME_FLAG_NAME = {
    HTTP_V2_NO_FLAG: "NO_FLAG",
    HTTP_V2_ACK_FLAG: "ACK",
    HTTP_V2_END_STREAM_FLAG: "END_STREAM",
    HTTP_V2_END_HEADERS_FLAG: "END_HEADERS",
    HTTP_V2_PADDED_FLAG: "PADDED",
    HTTP_V2_PRIORITY_FLAG: "PRIORITY",
}


class HTTP2FrameHeader(object):
    """The HTTP/2 frame header class.

    +-----------------------------------------------+
    |                   Length (24)                 |
    +---------------+---------------+---------------+
    |    Type (8)   |   Flags (8)   |
    +-+-------------+---------------+---------------+
    |R|             Stream Identifier (31)          |
    +=+=============================================+
    |               Frame Payload (0...)          ...
    +-----------------------------------------------+

    :param _type: the frame type, e.g. a PUSH_PROMISE frame.
    :param _length: the PAYLOAD length for this frame.
    :param _sid: the stream identifier where this frame belongs.
    :param _flags: the frame flags, e.g. a HEADERS frame with a END_STREAM.
    """
    def __init__(self, _type, _length, _sid, _flags=None):
        HTTP2FrameHeader.check_frame_type(_type)
        HTTP2FrameHeader.check_frame_length(_length)
        HTTP2FrameHeader.check_frame_sid(_sid)
        HTTP2FrameHeader.check_frame_flags(_flags)

        self.__type = _type
        self.__length = _length
        self.__sid = _sid
        self.__flags = _flags

    def __repr__(self):
        return "<HTTP/2 Frame header [%s]>" %
                    HTTP2FrameHeader.get_frame_name(self.__type)

    def serialize(self):
        """Serializes the frame header
        "rtype: string for python/2.x whereas bytes for python/3.x"
        """
        length_type = self.__length << 8 | self.__type
        return pack(">IBI", length_type, self.__flags, self.__sid)

    def has_flag(self, flag):
        return self.__flag & flag == flag

    @property
    def flags(self):
        """Returns the frame types."""
        return self.__flags

    @property
    def type(self):
        """Returns the frame type."""
        return self.__type

    @property
    def length(self):
        """Returns the frame payload length."""
        return self.__length

    @property
    def stream_id(self):
        """Returns the stream identifier."""
        return self.__sid

    @staticmethod
    def get_frame_type_name(_type):
        return HTTP_V2_FRAME_TYPE_NAME.get(_type, "UNKNOWN")

    @staticmethod
    def parse_frame_header(data):
        """Parses the data and builds a frame header.
        :param data: str/bytes data pends to parse. 
        :rtype: a instance of :class: `HTTP2FrameHeader`.

        for python/2.x, data shall be a str object,
        where as for python/3.x, data shall be a bytes object.
        """
        if is_py2 and not isinstance(data, str):
            raise ValueError("invalid param type '%s'" % type(data))
        elif is_py3 and not isinstance(data, bytes):
            raise ValueError("invalid param type '%s'" % type(data))

        if len(data) < HTTP_V2_FRAME_HEADER_SIZE:
            raise HTTP2FrameError("header size too small")

        data = data[:HTTP_V2_FRAME_HEADER_SIZE]
        return HTTP2FrameHeader(*unpack(">IBI", data))

    @staticmethod
    def check_frame_type(_type):
        """Checks validity for the frame type."""
        if _type < HTTP_V2_DATA_FRAME or _type > HTTP_V2_CONTINUATION_FRAME:
            raise HTTP2FrameError("invalid frame type 0x%x." % _type)

    @staticmethod
    def check_frame_length(_length):
        """Checks validity for the frame length."""
        if _length < 0 or _length > HTTP_V2_MAX_FRAME_SIZE:
            raise HTTP2FrameError("invalid frame length %d." % _length)

    @staticmethod
    def check_frame_sid(_sid, client=True):
        """Checks validity for the stream identifier where the frame belongs.
        Note the parity is not checked.
        """
        if _sid < 0 or _sid > HTTP_V2_STREAM_ID_MASK:
            raise HTTP2FrameError("invalid frame stream identifier: %d." % _sid)

    @staticmethod
    def check_frame_flags(_flags):
        """Checks validity for the frame flags."""
        dummy = 0
        for flag in HTTP_V2_FRAME_FLAG_NAME:
            if _flags & flag == flag:
                dummy |= flag

        if dummy != _flags:
            raise HTTP2FrameError("invalid frame flags: 0x%x." % flags)


class HTTP2HeadersFrame(object):
    """The HTTP/2 Headers frame class

    +-----------------+
    | Pad Length? (8) |
    +-+---------------+-----------------------------------------------+
    |E|                 Stream Dependency? (31)                       |
    +-+-------------+-------------------------------------------------+
    |  Weight? (8)  |
    +-+-------------+-------------------------------------------------+
    |                   Header Block Fragment (*)                   ...
    +-----------------------------------------------------------------+
    |                   Padding (*)                                 ...
    +-----------------------------------------------------------------+
    
    :param authority: the authority portion of the target URI.
    :param path: the path and query parts of the target URI.
    :param method: the HTTP method.
    :param headers: a dict represents the request headers.
    :param sid: the stream identifier where the frame belongs.
    :param flags: the frame flags.
    """
    def __init__(self, authority, path, method, headers, sid, flags=0):
        # the frame header
        self.__header = None

        self.header_block = dict((key.lower(), headers[key]) for key in headers)

        # pseudo-headers
        self.header_block[":authority"] = authority
        self.header_block[":method"] = method
        self.header_block[":path"] = path

    def serialize(self):
        pass


class HTTP2DataFrame(object):
    """The HTTP/2 Data frame class

    +---------------+
    |Pad Length? (8)|
    +---------------+-----------------------------------------------+
    |                           Data (*)                          ...
    +---------------------------------------------------------------+
    |                           Padding (*)                       ...
    +---------------------------------------------------------------+

    :param header: a instance of :class: `HTTP2FrameHeader`.
    :param _data: the body data.
    :param _pad: the padding data.
    """
    def __init__(self, _header, _data, _pad=None):
        pad_flag = _header.has_flag(HTTP_V2_PADDED_FLAG)
        if pad_flag and _pad is None:
            raise HTTP2FrameError("PADDED frame without padding data")
        elif not pad_flag and _pad is not None:
            raise HTTP2FrameError("Non PADDED frame with padding data")

        self.__header = _header
        self.__data = _data
        self.__pad = _pad

    def serialize(self):
        """Serializes the Data frame."""
        header = self.__header.serialize()

        data = empty_object
        if self.__header.has_flag(HTTP_V2_PADDED_FLAG) is not None:
            data = pack("B", len(self.__pad))

        return empty_object.join([data, self.__data, self.__pad])

    @staticmethod
    def parse_data_frame(self, header, payload):
        """Parses the DATA frame.
        Caller should assure that the payload size is equal to header.length.

        :param header: a instance of :class: `HTTP2FrameHeader`.
        :param payload: data stream.
        :rtype: a instance of :class: `HTTP2DataFrame`.
        """
        if header.type != HTTP_V2_DATA_FRAME:
            raise HTTP2FrameError("invalid frame type: %s" %
                HTTP2FrameHeader.get_frame_name(header.type))

        pad_length = 0
        if header.has_flag(HTTP_V2_PADDED_FLAG):
            if len(header.length) == 0:
                raise HTTP2FrameError("PADDED DATA frame "
                                      "with incorrect length: 0")

            pad_length, payload = payload[0], payload[1:]

        if pad_length >= header.length:
            raise HTTP2FrameError("DATA frame with incorrect length: %d "
                                  "padding: %d" % (header.length, pad_length))

        data_length = header.length - pad_length
        if pad_length == 0:
            return HTTP2DataFrame(header, payload)
        else:
            return HTTP2DataFrame(header, payload[:data_length],
                                  Payload[data_length:])
