# -*- coding: utf-8 -*-
"""
test_invalid_headers.py
~~~~~~~~~~~~~~~~~~~~~~~

This module contains tests that use invalid header blocks, and validates that
they fail appropriately.
"""
import pytest

import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.utilities

from hypothesis import given
from hypothesis.strategies import binary, lists, tuples

HEADERS_STRATEGY = lists(tuples(binary(), binary()))


class TestInvalidFrameSequences(object):
    """
    Invalid header sequences cause ProtocolErrors to be thrown when received.
    """
    base_request_headers = [
        (':authority', 'example.com'),
        (':path', '/'),
        (':scheme', 'https'),
        (':method', 'GET'),
        ('user-agent', 'someua/0.0.1'),
    ]
    invalid_header_blocks = [
        base_request_headers + [('Uppercase', 'name')],
        base_request_headers + [(':late', 'pseudo-header')],
        [(':path', 'duplicate-pseudo-header')] + base_request_headers,
        base_request_headers + [('connection', 'close')],
        base_request_headers + [('proxy-connection', 'close')],
        base_request_headers + [('keep-alive', 'close')],
        base_request_headers + [('transfer-encoding', 'gzip')],
        base_request_headers + [('upgrade', 'super-protocol/1.1')],
        base_request_headers + [('te', 'chunked')],
        base_request_headers + [('host', 'notexample.com')],
        [header for header in base_request_headers
         if header[0] != ':authority'],
    ]

    @pytest.mark.parametrize('headers', invalid_header_blocks)
    def test_headers_event(self, frame_factory, headers):
        """
        Test invalid headers are rejected with PROTOCOL_ERROR.
        """
        c = h2.connection.H2Connection(client_side=False)
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        f = frame_factory.build_headers_frame(headers)
        data = f.serialize()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.receive_data(data)

        expected_frame = frame_factory.build_goaway_frame(
            last_stream_id=1, error_code=h2.errors.PROTOCOL_ERROR
        )
        assert c.data_to_send() == expected_frame.serialize()

    def test_transfer_encoding_trailers_is_valid(self, frame_factory):
        """
        Transfer-Encoding trailers is allowed by the filter.
        """
        headers = (
            self.base_request_headers + [('te', 'trailers')]
        )

        c = h2.connection.H2Connection(client_side=False)
        c.receive_data(frame_factory.preamble())

        f = frame_factory.build_headers_frame(headers)
        data = f.serialize()

        events = c.receive_data(data)
        assert len(events) == 1
        request_event = events[0]
        assert request_event.headers == headers


class TestSendingInvalidFrameSequences(object):
    """
    Trying to send invalid header sequences cause ProtocolErrors to
    be thrown.
    """
    base_request_headers = [
        (':authority', 'example.com'),
        (':path', '/'),
        (':scheme', 'https'),
        (':method', 'GET'),
        ('user-agent', 'someua/0.0.1'),
    ]
    invalid_header_blocks = [
        base_request_headers + [('host', 'notexample.com')],
        [header for header in base_request_headers
         if header[0] != ':authority'],
    ]

    @pytest.mark.parametrize('headers', invalid_header_blocks)
    def test_headers_event(self, frame_factory, headers):
        """
        Test sending invalid headers raise a ProtocolError.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        # Clear the data, then try to send headers.
        c.clear_outbound_data_buffer()
        with pytest.raises(h2.exceptions.ProtocolError):
            c.send_headers(1, headers)


class TestFilter(object):
    """
    Test the filter function directly.

    These tests exists to confirm the behaviour of the filter function in a
    wide range of scenarios. Many of these scenarios may not be legal for
    HTTP/2 and so may never hit the function, but it's worth validating that it
    behaves as expected anyway.
    """
    validation_functions = [
        h2.utilities.validate_headers,
        h2.utilities.validate_sent_headers
    ]

    hdr_validation_combos = [
        h2.utilities.HeaderValidationFlags(is_client, is_trailer)
        for is_client, is_trailer in [
            (True, True),
            (True, False),
            (False, True),
            (False, False)
        ]
    ]

    @pytest.mark.parametrize('validation_function', validation_functions)
    @pytest.mark.parametrize('hdr_validation_flags', hdr_validation_combos)
    @given(headers=HEADERS_STRATEGY)
    def test_range_of_acceptable_outputs(self,
                                         headers,
                                         validation_function,
                                         hdr_validation_flags):
        """
        The header validation functions either return the data unchanged
        or throw a ProtocolError.
        """
        try:
            assert headers == list(validation_function(
                headers, hdr_validation_flags))
        except h2.exceptions.ProtocolError:
            assert True

    @pytest.mark.parametrize('hdr_validation_flags', hdr_validation_combos)
    def test_invalid_pseudo_headers(self, hdr_validation_flags):
        headers = [(b':custom', b'value')]
        with pytest.raises(h2.exceptions.ProtocolError):
            h2.utilities.validate_headers(headers, hdr_validation_flags)

    @pytest.mark.parametrize('validation_function', validation_functions)
    @pytest.mark.parametrize('hdr_validation_flags', hdr_validation_combos)
    def test_matching_authority_host_headers(self,
                                             validation_function,
                                             hdr_validation_flags):
        """
        If a header block has :authority and Host headers and they match,
        the headers should pass through unchanged.
        """
        headers = [
            (b':authority', b'example.com'),
            (b':path', b'/'),
            (b':scheme', b'https'),
            (b':method', b'GET'),
            (b'host', b'example.com'),
        ]
        assert headers == h2.utilities.validate_headers(
            headers, hdr_validation_flags)
