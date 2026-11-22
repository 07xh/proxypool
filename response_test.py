#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Purely local regressions for upstream completeness and request timeouts."""
import asyncio
import unittest
from unittest.mock import patch

import poolsd


class FakeWriter:
    def __init__(self):
        self.buffer = b""

    def write(self, value):
        self.buffer += value

    async def drain(self):
        pass

    def close(self):
        pass


class ResponseAndTimeoutTests(unittest.TestCase):
    def test_health_check_reads_close_delimited_response(self):
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nready")
            reader.feed_eof()
            return await poolsd._read_simple_response(reader, max_bytes=100)
        status, _, body = asyncio.run(run())
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ready")

    def test_health_check_204_without_body(self):
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b"HTTP/1.1 204 No Content\r\n\r\n")
            reader.feed_eof()
            return await poolsd._read_simple_response(reader, max_bytes=100)
        status, _, body = asyncio.run(run())
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")

    def test_oversized_response_is_rejected_not_truncated(self):
        gateway = poolsd.Gateway.__new__(poolsd.Gateway)
        gateway.idle_timeout = 1.0
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b"ABCDEFGHIJKLMNOP")
            reader.feed_eof()
            return await gateway._relay_response(reader, None)
        with patch.object(poolsd, "MAX_RESPONSE_BYTES", 10):
            with self.assertRaises(poolsd.BodyTooLarge):
                asyncio.run(run())

    def test_incomplete_response_timeout_is_error(self):
        gateway = poolsd.Gateway.__new__(poolsd.Gateway)
        gateway.idle_timeout = 0.02
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\npartial")
            return await gateway._relay_response(reader, None)
        with self.assertRaises(asyncio.TimeoutError):
            asyncio.run(run())

    def test_gateway_rejects_stalled_request_body(self):
        gateway = poolsd.Gateway.__new__(poolsd.Gateway)
        gateway.idle_timeout = 0.02
        async def run():
            reader = asyncio.StreamReader()
            writer = FakeWriter()
            await gateway._do_forward("POST http://example.invalid/ HTTP/1.1",
                                      [("Content-Length", "5")], reader, writer)
            return writer.buffer
        response = asyncio.run(run())
        self.assertTrue(response.startswith(b"HTTP/1.1 408"))

    def test_api_rejects_stalled_request_body(self):
        api = poolsd.ApiServer.__new__(poolsd.ApiServer)
        api.request_timeout = 0.02
        api.token = ""
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b"POST /add HTTP/1.1\r\nContent-Length: 5\r\n\r\n")
            writer = FakeWriter()
            await api.handle(reader, writer)
            return writer.buffer
        response = asyncio.run(run())
        self.assertTrue(response.startswith(b"HTTP/1.1 408"))
        self.assertIn(b"request_timeout", response)

    def test_complete_fixed_length_response(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        poolsd.ensure_complete_upstream_response(payload)

    def test_early_eof_with_content_length_is_rejected(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello"
        with self.assertRaises(poolsd.MalformedBody):
            poolsd.ensure_complete_upstream_response(payload)

    def test_valid_chunked_response_and_trailer(self):
        payload = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                   b"5\r\nhello\r\n0\r\nX-Trace: done\r\n\r\n")
        poolsd.ensure_complete_upstream_response(payload)

    def test_truncated_chunked_response_is_rejected(self):
        payload = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                   b"5\r\nhel")
        with self.assertRaises(poolsd.MalformedBody):
            poolsd.ensure_complete_upstream_response(payload)

    def test_informational_response_before_final_response(self):
        payload = (b"HTTP/1.1 100 Continue\r\n\r\n"
                   b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        poolsd.ensure_complete_upstream_response(payload)

    def test_head_response_may_declare_length_without_body(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"
        poolsd.ensure_complete_upstream_response(payload, "HEAD")
        with self.assertRaises(poolsd.MalformedBody):
            poolsd.ensure_complete_upstream_response(payload, "GET")

    def test_204_response_without_payload(self):
        poolsd.ensure_complete_upstream_response(b"HTTP/1.1 204 No Content\r\n\r\n")

    def test_premature_eof_relay_fails_closed(self):
        gateway = poolsd.Gateway.__new__(poolsd.Gateway)
        gateway.idle_timeout = 1.0
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nshort")
            reader.feed_eof()
            return await gateway._relay_response(reader, None)
        with self.assertRaises(poolsd.MalformedBody):
            asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
