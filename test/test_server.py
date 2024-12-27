import importlib.metadata
import os
from random import choices
from shutil import rmtree
from signal import SIGALRM, alarm, signal
from typing import Any, Callable, Dict
from unittest import TestCase, main, mock
from unittest.mock import Mock, mock_open, patch

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


class TestServer(TestCase):
    def setUp(self) -> None:
        self.r = CliRunner()
        with self.r.isolated_filesystem(temp_dir="/tmp/"):
            self.keydir = os.getcwd()
            sp, ss = skem.keypair()
            dp, ds = dh.dh_keypair()
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

    def tearDown(self) -> None:
        rmtree(self.keydir)

    def test_normal_main(self) -> None:
        try:
            # Automatically kill process
            signal(SIGALRM, handle)
            alarm(6)
            res = self.r.invoke(m, ["-i", "pqc-test"])

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
        """Check that invalid address throws a ValueError"""
        res = self.r.invoke(m, ["--addr", "hello"])
        self.assertTrue(isinstance(res.exception, ValueError))

    def test_verbose(self) -> None:
        """Check that verbose flags change logging level"""
        try:
            signal(SIGALRM, handle)
            alarm(3)
            res = self.r.invoke(m, ["-v"])
        except KeyboardInterrupt:
            self.assertEqual(logger.getEffectiveLevel(), 10)

    def test_very_verbose(self) -> None:
        try:
            signal(SIGALRM, handle)
            alarm(3)
            res = self.r.invoke(m, ["-vv"])
        except KeyboardInterrupt:
            self.assertEqual(logger.getEffectiveLevel(), 9)

    def test_missing_key(self) -> None:
        """Check that"""
        with self.r.isolated_filesystem(temp_dir="/tmp/"):
            with open("mceliece_pk", "wb") as f:
                f.write(b"0" * skem.PUBLICKEYBYTES)

            with open("x25519_pk", "wb") as f:
                f.write(b"0" * dh.lib25519_dh_PUBLICKEYBYTES)

            res = self.r.invoke(m, ["-d", "."])
            self.assertEqual(res.exit_code, 1)

            with open("session_key", "wb") as f:
                f.write(b"0" * 32)


if __name__ == "__main__":
    main()
