import importlib.metadata
import os
from random import choices
from signal import SIGALRM, alarm, signal
from typing import Any, Callable, Dict
from unittest import TestCase, main, mock, skip
from unittest.mock import Mock, mock_open, patch

import pytest
from click.testing import CliRunner
from pqconnect.common.constants import (
    MCELIECE_PK_PATH,
    MCELIECE_SK_PATH,
    SESSION_KEY_PATH,
    X25519_PK_PATH,
    X25519_SK_PATH,
)
from pqconnect.common.crypto import dh, skem
from pqconnect.log import logger
from pqconnect.server import main as m


def handle(signum: int, _: Any) -> None:
    raise KeyboardInterrupt


@skip("improper shutdown leading to orphaned port")
class TestServer(TestCase):
    def setUp(self) -> None:
        self.r = CliRunner()

    def tearDown(self) -> None:
        pass

    def test_normal_main(self) -> None:
        with self.r.isolated_filesystem():
            self.keydir = os.getcwd()
            sp, ss = skem.keypair()
            dp, ds = dh.keypair()
            sk = os.urandom(32)

            for key, path in zip(
                [sp, ss, dp, ds, sk],
                map(
                    os.path.basename,
                    [
                        MCELIECE_PK_PATH,
                        MCELIECE_SK_PATH,
                        X25519_PK_PATH,
                        X25519_SK_PATH,
                        SESSION_KEY_PATH,
                    ],
                ),
            ):
                with open(str(path), "wb") as f:
                    f.write(key)
            try:
                # Automatically kill process
                signal(SIGALRM, handle)
                alarm(6)
                res = self.r.invoke(m, ["-i", "pqc-test", "-d", "."])

            except KeyboardInterrupt:
                self.assertEqual(res.exit_code, 0)

    def test_click_invalid_directory(self) -> None:
        """Tests custom key directory"""
        with self.r.isolated_filesystem():
            res = self.r.invoke(m, ["-d", "magic"])

            # invalid click input gives exit code 2
            self.assertEqual(res.exit_code, 2)

    def test_version(self) -> None:
        res = self.r.invoke(m, ["--version"])
        VERSION = importlib.metadata.version("pqconnect")
        self.assertEqual(res.output.strip().split(" ")[-1], str(VERSION))

    def test_invalid_addr(self) -> None:
        """Check that invalid address causes an error"""
        with self.r.isolated_filesystem():
            self.keydir = os.getcwd()
            sp, ss = skem.keypair()
            dp, ds = dh.keypair()
            sk = os.urandom(32)

            for key, path in zip(
                [sp, ss, dp, ds, sk],
                map(
                    os.path.basename,
                    [
                        MCELIECE_PK_PATH,
                        MCELIECE_SK_PATH,
                        X25519_PK_PATH,
                        X25519_SK_PATH,
                        SESSION_KEY_PATH,
                    ],
                ),
            ):
                with open(str(path), "wb") as f:
                    f.write(key)

            res = self.r.invoke(m, ["--addr", "hello", "-d", "."])
            self.assertEqual(res.exit_code, 1)

    def test_verbose(self) -> None:
        """Check that verbose flags change logging level"""
        with self.r.isolated_filesystem():
            try:
                signal(SIGALRM, handle)
                alarm(3)
                res = self.r.invoke(m, ["-v"])
            except KeyboardInterrupt:
                self.assertEqual(logger.getEffectiveLevel(), 10)

    def test_very_verbose(self) -> None:
        with self.r.isolated_filesystem():
            try:
                signal(SIGALRM, handle)
                alarm(3)
                res = self.r.invoke(m, ["-vv"])
            except KeyboardInterrupt:
                self.assertEqual(logger.getEffectiveLevel(), 9)

    def test_missing_key(self) -> None:
        """Check that"""
        with self.r.isolated_filesystem():
            with open("mceliece_pk", "wb") as f:
                f.write(b"0" * skem.PUBLICKEYBYTES)

            with open("x25519_pk", "wb") as f:
                f.write(b"0" * dh.PUBLICKEYBYTES)

            res = self.r.invoke(m, ["-d", "."])
            self.assertEqual(res.exit_code, 2)


if __name__ == "__main__":
    main()
