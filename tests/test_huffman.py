# -*- coding: utf-8 -*-

"""Tests for HTTP/2 Huffman encoding and decoding."""

import pytest
import http2_adapter

from .compat import unit_type


class TestHTTP2Huffman:
    def test_entry_points(self):
        http2_adapter.HTTP2Huffman
        http2_adapter.HTTP2Huffman()

    def test_encode_and_decode(self):
        h = http2_adapter.HTTP2Huffman()

        def _t(__data, lower=False):
            data_after_encoding = h.encode(__data, lower)
            data_after_decoding = h.decode(data_after_encoding)
            if lower:
                assert data_after_decoding == __data.lower()
            else:
                assert data_after_decoding == __data

        _t(unit_type("H"))
        _t(unit_type("Hello World!@#$!!*&?"), lower=True)
        _t(unit_type("Hello World!@#$!!*&?"))
        _t(unit_type("Hello VVVVWorld!@#$!!*&?"))
        _t(unit_type("ASDIuu393849Hello VVVVWorld!@#$!!*&?"))
        _t(unit_type("1234567890-_=+qwertyuiop[]{}\\|asdfghjkl:;"))
