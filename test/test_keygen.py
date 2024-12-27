import stat
from os import environ, getcwd, listdir
from os import lstat as st
from os import mkdir, remove, rmdir
from os.path import basename, join
from unittest import TestCase, main, mock
from unittest.mock import Mock

from click.testing import CliRunner
from pqconnect.common.constants import CONFIG_PATH, DEFAULT_KEYPATH
from pqconnect.keygen import main as m
from pqconnect.keygen import save_keys, static_keygen


class TestKeyGen(TestCase):
    def setUp(self) -> None:
        self.cli = CliRunner()

    @mock.patch("builtins.input", return_value="y")
    def test_save_keys_create_dir(self, mocked_input: Mock) -> None:
        with self.cli.isolated_filesystem():
            self.assertTrue(
                save_keys("some_path", b"0", b"1", b"2", b"3", b"4")
            )

    @mock.patch("builtins.input", return_value="")
    def test_save_keys_create_dir_decline(self, mocked_input: Mock) -> None:
        with self.cli.isolated_filesystem():
            self.assertFalse(
                save_keys("some_path_new", b"0", b"1", b"2", b"3", b"4")
            )

    @mock.patch("builtins.input", return_value="y")
    def test_file_perms(self, mocked_input: Mock) -> None:
        """Tests that keys are saved with correct umask"""
        path = "some_path"
        with self.cli.isolated_filesystem():
            save_keys(path, b"0", b"1", b"2", b"3", b"4")

            for name in ["mceliece_sk", "x25519_sk", "session_key"]:
                print(f"\033[92m{name}:..\033[0m", end="")
                perms = st(join(path, name))
                self.assertFalse(
                    perms.st_mode
                    & (
                        stat.S_IRGRP
                        | stat.S_IWGRP
                        | stat.S_IXGRP
                        | stat.S_IWOTH
                        | stat.S_IROTH
                        | stat.S_IXOTH
                    )
                )
                print("\033[92mGood\033[0m")

            for name in ["mceliece_pk", "x25519_pk"]:
                perms = st(join(path, name))
                print(f"\033[92m{name}:..\033[0m", end="")
                perms = st(join(path, name))
                self.assertFalse(
                    perms.st_mode
                    & (
                        stat.S_IWGRP
                        | stat.S_IXGRP
                        | stat.S_IWOTH
                        | stat.S_IXOTH
                    )
                )
                print("\033[92mGood\033[0m")

    @mock.patch("builtins.input", return_value="y")
    def test_save_keys(self, mocked_input: Mock) -> None:
        """Tests that keys are saved as intended"""
        path = "some_path"
        with self.cli.isolated_filesystem():
            save_keys(path, b"0", b"1", b"2", b"3", b"4")

            try:
                with open(join(path, "mceliece_pk"), "rb") as f:
                    self.assertEqual(f.read(), b"0")
                    f.close()

                with open(join(path, "mceliece_sk"), "rb") as f:
                    self.assertEqual(f.read(), b"1")
                    f.close()

                with open(join(path, "x25519_pk"), "rb") as f:
                    self.assertEqual(f.read(), b"2")
                    f.close()

                with open(join(path, "x25519_sk"), "rb") as f:
                    self.assertEqual(f.read(), b"3")
                    f.close()

                with open(join(path, "session_key"), "rb") as f:
                    self.assertEqual(f.read(), b"4")
                    f.close()

            except FileNotFoundError as e:
                self.assertTrue(False, e)

    def test_static_keygen(self) -> None:
        """test that static_keygen succeeds"""
        with self.cli.isolated_filesystem():
            self.assertTrue(static_keygen(".", 12345, 54321, False))

    @mock.patch("builtins.input")
    def test_static_keygen_fail(self, mocked: Mock) -> None:
        """check that static keygen returns False if user has no directory
        write permissions

        """
        path = "test_static_keygen_fail"
        pqcport = 12345
        keyport = 54321
        dns_only = False
        # new key path, this will prompt the function to ask to mkdir
        # say no
        mocked.return_value = "N"

        self.assertFalse(
            static_keygen(path, pqcport, keyport, dns_only),
            "should not be able to write keys to disk",
        )

        # mkdir again so that the tearDown doesn't throw an exception
        mocked.return_value = "y"
        self.assertTrue(
            static_keygen(path, pqcport, keyport, dns_only),
            "should not be able to write keys to disk",
        )

    @mock.patch("builtins.input")
    def test_click(self, mocked: Mock) -> None:
        mocked.side_effect = ["y", "12345", "54321", "y"]
        keypath = basename(DEFAULT_KEYPATH)
        configpath = basename(CONFIG_PATH)
        with self.cli.isolated_filesystem():
            res = self.cli.invoke(m, ["-d", keypath, "-c", configpath])
            self.assertEqual(res.exit_code, 0)

            # test dns_only flag
            res = self.cli.invoke(m, ["-d", keypath, "-c", configpath, "-D"])
            self.assertEqual(res.exit_code, 0)


if __name__ == "__main__":
    main()
