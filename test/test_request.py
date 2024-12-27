from unittest import TestCase

from pqconnect.common.constants import EPHEMERAL_KEY_REQUEST
from pqconnect.common.crypto import dh, ekem
from pqconnect.request import (
    EphemeralKeyRequest,
    EphemeralKeyResponse,
    KeyRequest,
    KeyRequestHandler,
    KeyResponseHandler,
    StaticKeyRequest,
    StaticKeyResponse,
    UnexpectedRequestException,
    UnpackException,
)


class TestKeyRequest(TestCase):
    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def test_init(self) -> None:
        try:
            kr = KeyRequest(0)
            self.assertTrue(False, "wrong type")
        except TypeError:
            self.assertTrue(True)

        try:
            kr = KeyRequest(b"\x00\x00")
            self.assertTrue(True)
        except Exception:
            self.assertTrue(False)

    def test_pack(self) -> None:
        msg_type = b"\x01\xff"
        try:
            kr = KeyRequest(msg_type)
            kr._pack_bts([1, b"1"])
            self.assertTrue(False, "Should have thrown a TypeError")
        except TypeError:
            self.assertTrue(True)

        try:
            kr._pack_bts(["1", b"1"])
            self.assertTrue(False, "Should have thrown a TypeError")
        except TypeError:
            self.assertTrue(True)

        try:
            kr._pack_bts([b"hello", b"goodbye"])
            self.assertEqual(
                kr.payload, msg_type + b"\x00\x05hello\x00\x07goodbye"
            )

        except Exception:
            self.assertTrue(False)

    def test_unpack(self) -> None:
        msg_type = b"\x01\xf1"  # no significance
        payload = msg_type + b"\x00\x05hello\x00\x07goodbye"
        payload_wrong0 = payload + b"\x00\x00"
        payload_wrong1 = payload + b"\x00\x01"
        payload_wrong2 = msg_type + b"\x00\x05hello\x00\x08goodbye"

        try:
            kr = KeyRequest(msg_type=msg_type, payload=payload)
            vals = kr._unpack_bts()
            self.assertEqual(vals[0], b"hello")
            self.assertEqual(vals[1], b"goodbye")
            self.assertEqual(len(vals), 2)
        except Exception:
            self.assertTrue(False)

        try:
            kr = KeyRequest(msg_type, payload_wrong0)
            vals = kr._unpack_bts()
            self.assertTrue(False, "Extraneous zero-length value undetected")
        except UnpackException:
            self.assertTrue(True)

        try:
            kr = KeyRequest(msg_type, payload_wrong1)
            vals = kr._unpack_bts()
            self.assertTrue(False, "payload too long")
        except UnpackException:
            self.assertTrue(True)

        try:
            kr = KeyRequest(msg_type, payload_wrong2)
            vals = kr._unpack_bts()
            self.assertTrue(False, "payload truncated")
        except UnpackException:
            self.assertTrue(True)


class TestKeyRequestHandler(TestCase):
    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def test_request_handler(self) -> None:
        """Tests that correct request is returned"""
        skr = StaticKeyRequest(depth=2, pos=20).payload

        eph_request = EphemeralKeyRequest()
        ekr = bytes(eph_request)

        handler_request = KeyRequestHandler(skr).request()
        self.assertTrue(isinstance(handler_request, StaticKeyRequest))
        self.assertEqual(handler_request.depth, 2)
        self.assertEqual(handler_request.pos, 20)

        handler_request1 = KeyRequestHandler(ekr).request()
        self.assertTrue(
            isinstance(handler_request1, EphemeralKeyRequest),
            type(handler_request1),
        )


class TestResponseHandler(TestCase):
    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def test_response(self) -> None:
        sreq = StaticKeyResponse(depth=2, pos=25, keydata=b"Hi")
        resp = KeyResponseHandler(sreq.payload).response()
        self.assertTrue(isinstance(resp, StaticKeyResponse))

        ereq = EphemeralKeyResponse(pqpk=b"0" * ekem.pklen, npqpk=b"0" * 32)
        resp = KeyResponseHandler(ereq.payload).response()
        self.assertTrue(isinstance(resp, EphemeralKeyResponse))


class TestEphemeralRequestResponse(TestCase):
    def test_same_size(self) -> None:
        req = EphemeralKeyRequest()
        sntrup, _ = ekem.keypair()
        ecc, _ = dh.dh_keypair()
        resp = EphemeralKeyResponse(pqpk=sntrup, npqpk=ecc)
        self.assertEqual(len(bytes(req)), len(bytes(resp)))
