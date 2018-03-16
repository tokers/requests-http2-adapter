# -*- coding: utf-8 -*-

"""
http/2 protocol frame implements
"""

from .compat import is_py2, is_py3
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

    This class should not be used from user code, instead, it is designed only
    for inheritence.

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
        :rtype: a instances of :class: `HTTP2FrameHeader`.

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
        if not isinstance(_type, int):
            raise ValueError("frame type should be an integer.")
        elif _type < HTTP_V2_DATA_FRAME or _type > HTTP_V2_CONTINUATION_FRAME:
            raise HTTP2FrameError("invalid frame type 0x%x." % _type)

    @staticmethod
    def check_frame_length(_length):
        """Checks validity for the frame length."""
        if not isinstance(_type, int):
        if not isinstance(_length, int):
            raise ValueError("frame length should be an integer.")
        elif _length < 0 or _length > HTTP_V2_MAX_FRAME_SIZE:
            raise HTTP2FrameError("invalid frame length %d." % _length)

    @staticmethod
    def check_frame_sid(_sid, client=True):
        """Checks validity for the stream identifier where the frame belongs.
        Note the parity is not checked.
        """
        if not isinstance(_sid, int):
            raise ValueError("frame stream identifier should be a integer.")
        elif _sid < 0 or _sid > HTTP_V2_STREAM_ID_MASK:
            raise HTTP2FrameError("invalid frame stream identifier: %d." % _sid)

    @staticmethod
    def check_frame_flags(_flags):
        """Checks validity for the frame flags."""
        if not isinstance(_flags, int):
            raise ValueError("frame flags should be a integer.")

        mimic = 0
        for flag in HTTP_V2_FRAME_FLAG_NAME:
            if _flags & flag == flag:
                mimic |= flag

        if mimic != _flags:
            raise HTTP2FrameError("invalid frame flags: 0x%x." % flags)


class HTTP2HeadersFrame(HTTP2FrameHeader):
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
    """
    def __init__(self, authority, path, method, sid, headers, flags=None):
        pass
