# -*- coding: utf-8 -*-

"""
http/2 adapter implements
~~~~~~~~~~~~~

This module contains the transport adapters that Requests uses to define
and maintain connections.
"""


import requests

from requests.exceptions import InvalidSchema as _SchemaError

from urllib3.poolmanager import PoolManager, proxy_from_url
from urllib3.util.retry import Retry
from urllib3.util import parse_url

from urllib3.exceptions import ClosedPoolError
from urllib3.exceptions import ConnectTimeoutError
from urllib3.exceptions import HTTPError as _HTTPError
from urllib3.exceptions import MaxRetryError
from urllib3.exceptions import NewConnectionError
from urllib3.exceptions import ProxyError as _ProxyError
from urllib3.exceptions import ProtocolError
from urllib3.exceptions import ReadTimeoutError
from urllib3.exceptions import SSLError as _SSLError
from urllib3.exceptions import ResponseError


DEFAULT_POOLBLOCK = False
DEFAULT_POOLSIZE = 10
DEFAULT_RETRIES = 0
DEFAULT_POOL_TIMEOUT = None


class HTTP2Adapter(requests.adapters.BaseAdapter):
    """The HTTP/2 Adapter for urllib3

    Usage::

      >>> import requests
      >>> from http2_adapter import HTTP2Adapter
      >>> s = requests.Session()
      >>> a = HTTP2Adapter(max_retries=3)
      >>> s.mount("https://", a)
    """

    __attrs__ = ['max_retries', 'config', '_pool_connections', '_pool_maxsize',
                 '_pool_block']

    def __init__(self, pool_connections=DEFAULT_POOLSIZE,
                 pool_maxsize=DEFAULT_POOLSIZE, max_retries=DEFAULT_RETRIES,
                 pool_block=DEFAULT_POOLBLOCK):
        if max_retries == DEFAULT_RETRIES:
            self.max_retries = Retry(0, read=False)
        else:
            self.max_retries = Retry.from_int(max_retries)

        self.config = {}

        super(HTTP2Adapter, self).__init__()

        self._pool_connections = pool_connections
        self._pool_maxsize = pool_maxsize
        self._pool_block = pool_block

        self.init_poolmanager(pool_connections, pool_maxsize, block=pool_block)

    def __getstate__(self):
        return dict((attr, getattr(self, attr, None)) for attr in
                    self.__attrs__)

    def __setstate__(self, state):
        self.config = {}

        for attr, value in state.items():
            setattr(self, attr, value)

        self.init_poolmanager(self._pool_connections, self._pool_maxsize,
                              block=self._pool_block)

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK,
                         **pool_kwargs):
        """Initializes a urllib3 PoolManager.

        This method should not be called from user code, and is only
        exposed for use when subclassing the
        :class:`HTTPAdapter <requests.adapters.HTTPAdapter>`.

        :param connections: The number of urllib3 connection pools to cache.
        :param maxsize: The maximum number of connections to save in the pool.
        :param block: Block when no free connections are available.
        :param pool_kwargs: Extra keyword arguments used to initialize the Pool Manager.
        """

        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block

        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize,
                                       block=block, strict=True, **pool_kwargs)

    def cert_verify(self, conn, url, verify, cert):
        pass

    def get_connection(self, url):
        """Returns a urllib3 connection for the given URL. This should not be
        called from user code, and is only exposed for use when subclassing the
        :class:`HTTPAdapter <requests.adapters.HTTPAdapter>`.

        :param url: The URL to connect to.
        :rtype: urllib3.ConnectionPool
        """

        parsed = urlparse(url)
        url = parsed.geturl()

        return self.poolmanager.connection_from_url(url)

    def close(self):
        """Disposes of any internal state."""
        self.poolmanager.clear()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None):
        """Sends PreparedRequest object. Returns Response object.

        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple or urllib3 Timeout object
        :param verify: (optional) Either a boolean, in which case it controls whether
            we verify the server's TLS certificate, or a string, in which case it
            must be a path to a CA bundle to use
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :rtype: requests.Response
        """

        scheme = urlparse(request.url).scheme
        # FIXME supports the plain HTTP/2
        if scheme != "https":
            raise _SchemaError("unsupported schema: \"%s\"" % scheme)

        conn = self.get_connection(request.url)

        self.cert_verify(conn, request.url, verify, cert)
