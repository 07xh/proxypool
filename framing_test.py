#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP request framing regressions. No external services or real credentials."""
import asyncio
import unittest

import poolsd


def parse(data, headers, limit=poolsd.MAX_HEAD, strict=True):
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return await poolsd.read_body(reader, headers, limit=limit, strict=strict)
    return asyncio.run(run())


class RequestFramingTests(unittest.TestCase):
    def test_content_length_is_forwarded_once(self):
        headers = [("Content-Length", "5"), ("Content-Type", "text/plain")]
        body = parse(b"hello", headers)
        self.assertEqual(body, b"hello")
        wire = poolsd.Gateway._rebuild_headers(
            None, "POST http://example.invalid/ HTTP/1.1", headers,
            "example.invalid", body)
        self.assertEqual(wire.count(b"Content-Length:"), 1)
        self.assertIn(b"Content-Length: 5\r\n", wire)
        self.assertTrue(wire.endswith(b"\r\n\r\nhello"))

    def test_chunked_decoding_reframes_as_content_length(self):
        headers = [("Transfer-Encoding", "chunked"), ("Trailer", "X-Trace"),
                   ("Content-Type", "text/plain")]
        wire = b"4;ext=ok\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trace: discard\r\n\r\n"
        body = parse(wire, headers)
        self.assertEqual(body, b"Wikipedia")
        outgoing = poolsd.Gateway._rebuild_headers(
            None, "POST http://example.invalid/ HTTP/1.1", headers,
            "example.invalid", body)
        head, value = outgoing.split(b"\r\n\r\n", 1)
        self.assertNotIn(b"Transfer-Encoding", head)
        self.assertNotIn(b"Trailer:", head)
        self.assertIn(b"Content-Length: 9", head)
        self.assertEqual(value, b"Wikipedia")

    def test_ambiguous_framing_is_rejected(self):
        with self.assertRaises(poolsd.MalformedBody):
            parse(b"", [("Content-Length", "4"), ("Transfer-Encoding", "chunked")])
        with self.assertRaises(poolsd.MalformedBody):
            parse(b"", [("Content-Length", "4"), ("Content-Length", "4")])
        with self.assertRaises(poolsd.MalformedBody):
            parse(b"", [("Transfer-Encoding", "gzip, chunked")])
        with self.assertRaises(poolsd.MalformedBody):
            parse(b"", [("Content-Length", "-1")])

    def test_oversize_never_forwards_partial_request(self):
        with self.assertRaises(poolsd.BodyTooLarge):
            parse(b"", [("Content-Length", "12345")], limit=10)
        with self.assertRaises(poolsd.BodyTooLarge):
            parse(b"b\r\n", [("Transfer-Encoding", "chunked")], limit=10)

    def test_read_only_health_response_can_truncate(self):
        self.assertEqual(parse(b"abcdefghijkl", [("Content-Length", "12")],
                               limit=5, strict=False), b"abcde")
        self.assertEqual(parse(b"c\r\nabcdefghijkl\r\n0\r\n\r\n",
                               [("Transfer-Encoding", "chunked")],
                               limit=5, strict=False), b"abcde")

    def test_invalid_chunk_terminators_are_rejected(self):
        with self.assertRaises(poolsd.MalformedBody):
            parse(b"3\r\nabcxx0\r\n\r\n", [("Transfer-Encoding", "chunked")])

    def test_connection_scoped_headers_are_stripped(self):
        wire = poolsd.Gateway._rebuild_headers(
            None, "POST http://example.invalid/ HTTP/1.1",
            [("Connection", "X-Debug, keep-alive"), ("X-Debug", "remove"),
             ("Content-Length", "4"), ("Host", "wrong.invalid")],
            "example.invalid", b"test")
        self.assertNotIn(b"X-Debug", wire)
        self.assertNotIn(b"wrong.invalid", wire)
        self.assertIn(b"Host: example.invalid", wire)
        self.assertIn(b"Content-Length: 4", wire)


if __name__ == "__main__":
    unittest.main()
