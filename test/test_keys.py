from base64 import standard_b64decode as b64
from os import getcwd, mkdir, remove, rmdir, urandom
from os.path import join
from unittest import TestCase, main, mock

from pqconnect.common.crypto import dh, h, skem
from pqconnect.keys import InvalidNodeException, PKTree
from pymceliece import mceliece6960119, mceliece8192128


class TestKeys(TestCase):
    def setUp(self) -> None:
        self.pk, self.sk = skem.keypair()
        self.point, self.scalar = dh.dh_keypair()
        self.tree = PKTree(self.pk, self.point)

    def tearDown(self) -> None:
        pass

    def test___init__(self) -> None:
        """Tests that tree is constructed correctly by comparing to known
        vectors

        """
        try:
            tree = PKTree()
        except Exception:
            self.assertTrue(False, "exception thrown but shouldn't have")

        try:
            tree = PKTree(
                "a" * skem.PUBLICKEYBYTES, "b" * dh.lib25519_dh_PUBLICKEYBYTES
            )
            self.assertTrue(False, "Should have thrown exception")
        except TypeError:
            self.assertTrue(True)

        try:
            tree = PKTree(self.pk, self.point[:5])
            self.assertTrue(False, "Should have thrown exception")
        except ValueError:
            self.assertTrue(True)

        try:
            tree = PKTree(self.pk[:5], self.point)
            self.assertTrue(False, "Should have thrown exception")
        except ValueError:
            self.assertTrue(True)

    def test_from_file(self) -> None:
        with mock.patch("builtins.open", create=True) as mock_open:
            mock_open.return_value = mock.MagicMock()
            m_file = mock_open.return_value.__enter__.return_value
            reads = [self.pk, self.point]
            m_file.read.side_effect = lambda: reads.pop(0)

            try:
                tree = PKTree.from_file("mceliece", "x25519")
            except:
                self.assertFalse(True)

        try:
            tree = PKTree.from_file(
                "definitely_doesn't_exist", "booasdlfkjasdf"
            )
        except FileNotFoundError:
            self.assertTrue(True)
            return

        self.assertTrue(False, "Exception was not thrown")

    def test_get_node(self) -> None:
        try:
            self.tree.get_node(0, 0)
            self.assertTrue(True)
        except Exception:
            self.assertTrue(False)

        try:
            self.tree.get_node(1234, 1234)
            self.assertTrue(False, "should have raised ValueError")
        except InvalidNodeException:
            self.assertTrue(True)

        try:
            tree = PKTree()
            tree.get_node(0, 0)
            self.assertTrue(False, "Should have raise ValueError")
        except InvalidNodeException:
            self.assertTrue(True)

    def test_get_children_range(self) -> None:
        """Tests that get_children_range returns the range of nodes whose
        concatenated hashes create the node passed to the function

        Does this for all level 0, 1, and 2 nodes

        """
        try:
            a, b = PKTree.get_children_range(4, 0)
            self.assertTrue(False, "error not raised")
        except ValueError:
            self.assertTrue(True)

        if skem.PUBLICKEYBYTES == mceliece8192128:
            struct = {0: 1, 1: 1, 2: 33}
        else:
            struct = {0: 1, 1: 1, 2: 26}
        try:
            for i in range(3):
                for j in range(struct[i]):
                    childbts = b""
                    a, b = PKTree.get_children_range(i, j)
                    for k in range(a, b):
                        childbts += h(self.tree.get_node(i + 1, k))

                    self.assertEqual(childbts, self.tree.get_node(i, j))
        except Exception as e:
            self.assertTrue(False, e)

    def test_get_pks(self) -> None:
        """Checks that the public keys returns from the tree equal what was
        passed in construction

        """
        self.assertEqual(self.pk, self.tree.get_pqpk())
        self.assertEqual(self.point, self.tree.get_npqpk())

        tree = PKTree()
        self.assertEqual(b"", tree.get_pqpk())
        self.assertEqual(b"", tree.get_npqpk())

    def test_is_complete(self) -> None:
        self.assertTrue(self.tree.is_complete())
        del self.tree._tree[2][5]
        self.assertFalse(self.tree.is_complete())

    def test_get_subtree_packets_at_root(self) -> None:
        if skem.PUBLICKEYBYTES == mceliece8192128.PUBLICKEYBYTES:
            vecs = [
                ((0, 0), [(0, 0), (1, 0)]),
                ((1, 0), [(1, 0)]),
                ((2, 0), [(2, 0)] + [(3, i) for i in range(36)]),
                ((2, 32), [(2, 32)] + [(3, i) for i in range(1152, 1179)]),
                ((3, 0), [(3, 0)]),
            ]
        else:
            vecs = [
                ((0, 0), [(0, 0), (1, 0)]),
                ((1, 0), [(1, 0)]),
                ((2, 0), [(2, 0)] + [(3, i) for i in range(36)]),
                ((2, 25), [(2, 25)] + [(3, i) for i in range(900, 910)]),
                ((3, 0), [(3, 0)]),
            ]

        for inpt, output in vecs:
            a, b = inpt
            self.assertEqual(
                self.tree.get_subtree_packets_at_root(a, b), output
            )

        try:
            self.tree.get_subtree_packets_at_root(20, 5)
            self.assertTrue(False, "should have thrown ValueError")
        except InvalidNodeException:
            self.assertTrue(True)

        try:
            self.tree.get_subtree_packets_at_root(3, 2500)
            self.assertTrue(False, "should have thrown ValueError")
        except InvalidNodeException:
            self.assertTrue(True)

    def test_insert_node(self) -> None:
        tree = PKTree()
        self.assertTrue(tree.insert_node(0, 0, self.tree.get_node(0, 0)))
        self.assertTrue(tree.insert_node(0, 0, self.tree.get_node(0, 0)))
        self.assertTrue(tree.insert_node(1, 0, self.tree.get_node(1, 0)))
        self.assertTrue(tree.insert_node(2, 0, self.tree.get_node(2, 0)))
        self.assertFalse(tree.insert_node(3, 123, self.tree.get_node(3, 123)))
        self.assertFalse(tree.insert_node(123, 123, b"hello"))

    def test_insert_wrong_root(self) -> None:
        tree = PKTree()
        a = urandom(32)
        b = urandom(32)
        self.assertTrue(tree.insert_node(0, 0, a))
        self.assertFalse(tree.insert_node(0, 0, b))


if __name__ == "__main__":
    main()
