# -*- coding: utf-8 -*-

"""
http2-adapter.exceptions
~~~~~~~~~~~~~~~~~~~~~~~~

This module contains the set of HTTP/2 Adapter's exceptions.
"""

from requests.exceptions import RequestException


class HTTP2Error(RequestException):
    """An HTTP/2 error occurred."""


class HTTP2FrameError(HTTP2Error):
    """An HTTP/2 frame error occurred."""

