from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from pymceliece import mceliece6960119, mceliece8192128

from .common.constants import SEG_LEN
from .common.crypto import HLEN, dh, h, skem
from .common.util import base32_encode


class InvalidNodeException(Exception):
    """Raised when a non-existent node index is requested"""

    def __init__(self, depth: int, pos: int) -> None:
        super().__init__(f"No node at position {depth}, {pos}")


def _get_tree_dimensions(pklen: int, node_length: int) -> list[int]:
    """Returns the dimensions of a Merkle tree whose leaves contain a public
    key of length PKLEN (plus a 32-byte DH key) with node size equal to
    node_length

    Examples:
    >>> _get_tree_dimensions(1234, 64)
    [1, 1, 2, 3, 5, 10, 20]
    >>> _get_tree_dimensions(1357824, 1152)
    [1, 1, 33, 1179]
    >>> _get_tree_dimensions(1047319, 1152)
    [1, 1, 26, 910]
    """
    if node_length < HLEN:
        raise ValueError

    ret = []
    tot_bts = pklen + dh.lib25519_dh_PUBLICKEYBYTES  # +32
    while tot_bts > HLEN:  # levels below the root
        num_nodes = (tot_bts + node_length - 1) // node_length  # ceil
        ret.append(num_nodes)
        tot_bts = num_nodes * HLEN
    ret.append(1)  # 1 node at level 0 (root)
    ret.reverse()
    return ret


class _PKTree(ABC):
    @classmethod
    @abstractmethod
    def from_file(cls, pq_path: str, npq_path: str) -> _PKTree:
        pass

    @staticmethod
    @abstractmethod
    def get_children_range(depth: int, pos: int) -> tuple[int, int]:
        pass

    def __init__(
        self,
        pklen: int,
        pqpk: Optional[bytes] = None,
        npqpk: Optional[bytes] = None,
    ) -> None:
        """Builds a nested dict of key, dict pairs. The level 1 keys represent
        the depth of the tree. The keys of the inner dicts are the left-right
        positions of each packet in that level of the tree. The values of the
        inner dicts are contents of each packet the client can request. Follows
        the description in section 3.2.1 of the PQConnect thesis, using
        mceliece8192128:

        - The 1357856-byte mceliece8192128 key is split into 1179 parts, each
          part (before the last) having 1152 bytes. The 32-byte long-term
          x25519 public key is appended to the last part, which becomes 800
          bytes in total. (Depth 3)

        - Each leaf node is hashed separately, producing 37728 bytes in total.

        - These 37728 bytes are split into 33 groups of 36 hashes, again each
          part (before the last) having 1152 bytes. (Depth 2)

        - Each level 2 node is hashed independently. The hashes are
          concatenated, producing a single node of 1056 bytes. (Depth 1)

        - These 1056 bytes are hashed, producing the root of the tree. (Depth
          0)

              ()
              |
              ()
         / ...|...\
33:     ()....()...()
       /......|......\
1179: ()......().....()

        """
        self._tree: dict = {0: {}, 1: {}, 2: {}, 3: {}}

        # a dictionary holding the tree dimensions at each depth level
        dimensions = _get_tree_dimensions(pklen, SEG_LEN)

        self._struct: Dict[int, int] = dict(
            zip(range(len(dimensions)), dimensions)
        )

        if not pqpk or not npqpk:
            return

        if not (isinstance(pqpk, bytes) and isinstance(npqpk, bytes)):
            raise TypeError

        if len(pqpk) != pklen:
            raise ValueError

        if len(npqpk) != dh.lib25519_dh_PUBLICKEYBYTES:
            raise ValueError

        # Depth 3
        for i in range(pklen // SEG_LEN + 1):
            self._tree[3][i] = pqpk[
                i * SEG_LEN : min((i + 1) * SEG_LEN, pklen)
            ]
        # Append X25519 key to last node
        self._tree[3][self._struct[3] - 1] += npqpk

        # Depth 2
        # Concatenate hashes of level 3 nodes
        hash_bts = b"".join(
            [h(self._tree[3][i]) for i in range(len(self._tree[3]))]
        )
        # Divide bytes among level 2 nodes
        for i in range(len(hash_bts) // SEG_LEN + 1):
            self._tree[2][i] = hash_bts[
                i * SEG_LEN : min((i + 1) * SEG_LEN, len(hash_bts))
            ]

        # Depth 1
        # Hash and concatenate level 2 nodes into level 1 node
        self._tree[1][0] = b"".join(
            [h(self._tree[2][i]) for i in range(len(self._tree[2]))]
        )

        # Depth 0
        self._tree[0] = {0: h(self._tree[1][0])}

    def get_structure(self) -> Dict[int, int]:
        """Returns the dimensions of the tree as a Dict, indexed by depth"""
        return self._struct

    def get_pubkey_hash(self) -> bytes:
        """Returns the raw public key hash"""
        return self.get_node(0, 0)

    def get_base32_encoded_pubkey_hash(self, pk_hash: bytes = b"") -> str:
        """Returns the base32-encoded hash of the public keys stored in the
        tree

        """
        if pk_hash:
            pkh = pk_hash
        else:
            pkh = self.get_pubkey_hash()
        return base32_encode(pkh)

    def get_node(self, depth: int, pos: int) -> bytes:
        """Returns the bytes stored at position (depth, pos) in the tree"""
        try:
            return self._tree[depth][pos]
        except KeyError as e:
            raise InvalidNodeException(depth, pos) from e

    def get_npqpk(self) -> bytes:
        """Returns the x25519 public key"""
        try:
            return self.get_node(3, self._struct[3] - 1)[
                -dh.lib25519_dh_PUBLICKEYBYTES :
            ]
        except InvalidNodeException:
            return b""

    def get_pqpk(self) -> bytes:
        """Returns the McEliece public key"""
        try:
            return b"".join(
                [self.get_node(3, i) for i in range(self._struct[3])]
            )[: -dh.lib25519_dh_PUBLICKEYBYTES]
        except InvalidNodeException:
            return b""

    def is_complete(self) -> bool:
        """Returns true if the full public key data is stored and verified"""
        return all(
            [
                len(self._tree[i]) == self._struct[i]
                for i in self._struct.keys()
            ]
        )

    def insert_node(self, depth: int, pos: int, data: bytes) -> bool:
        """Verify and insert a packet into the PKTree"""
        # Return True if the data is already inserted (duplicate packet)
        if depth in self._tree and pos in self._tree[depth]:
            return data == self._tree[depth][pos]

        if self.verify_node(depth, pos, data):
            self._tree[depth][pos] = data
            return True

        return False

    def verify_node(self, depth: int, pos: int, data: bytes) -> bool:
        """Returns True if the hash of the data is contained in its parent node
        at the correct offset

        """
        try:
            if depth == 0:
                return True
            elif depth == 1:
                return h(data) == self._tree[0][0]
            elif depth == 2:
                idx = pos * HLEN
                return h(data) == self._tree[1][0][idx : idx + HLEN]
            elif depth == 3:
                idx = pos * 32 % SEG_LEN
                return h(data) == self._tree[2][pos // 36][idx : idx + HLEN]
            else:
                raise InvalidNodeException(depth, pos)
        except (InvalidNodeException, KeyError):
            return False

    def get_subtree_packets_at_root(
        self, depth: int, pos: int
    ) -> list[tuple[int, int]]:
        """Returns a list of tree indices rooted at the given node... sorta

        If the root is in the top half of the tree, just return the subtree
        restricted to the top half of the tree. This limits the result size for
        practical reasons.

        examples:
        PKTree.get_subtree_packets_at_root(0, 0) # [(0, 0), (1, 0)]
        PKTree.get_subtree_packets_at_root(1, 0) # [(1, 0)]
        PKTree.get_subtree_packets_at_root(2, 0) # [(2, 0), (3, 0), ... , (3, 35)]
        PKTree.get_subtree_packets_at_root(2, 32) # [(2, 32), (3, 1152), ... , (3, 1178)]
        PKTree.get_subtree_packets_at_root(3, 0) # [(3, 0)]

        """
        if depth not in self._struct.keys() or pos > self._struct[depth]:
            raise InvalidNodeException(depth, pos)

        ret = [(depth, pos)]
        if depth == 0:
            ret.append((1, pos))

        elif depth == 1:
            pass

        elif depth == 2:
            for j in range(pos * 36, min((pos + 1) * 36, self._struct[3])):
                ret.append((3, j))

        return ret


class _PKTree8192128(_PKTree):
    @classmethod
    def from_file(cls, pq_path: str, npq_path: str) -> _PKTree8192128:
        with open(pq_path, "rb") as f:
            pq = f.read()
            f.close()
        with open(npq_path, "rb") as f:
            npq = f.read()
            f.close()

        return cls(pq, npq)

    def __init__(
        self, pqpk: Optional[bytes] = None, npqpk: Optional[bytes] = None
    ):
        super().__init__(mceliece8192128.PUBLICKEYBYTES, pqpk, npqpk)

    @staticmethod
    def get_children_range(depth: int, pos: int) -> tuple[int, int]:
        """Returns the range of position indexes of the children of the node at
        the given position.

        Excample:
        get_children_range(0, 0)
        (0, 1)

        get_children_range(1, 0)
        (0, 33)

        get_children_range(2, 0)
        (0, 36)

        get_children_range(2, 32)
        (1152, 1179)

        """

        if depth not in range(0, 3):
            raise ValueError

        elif depth == 0:
            return (0, 1)

        elif depth == 1:
            return (0, 33)

        else:  # depth == 2:
            return (pos * 36, min((pos + 1) * 36, 1179))


class _PKTree6960119(_PKTree):
    @classmethod
    def from_file(cls, pq_path: str, npq_path: str) -> _PKTree6960119:
        with open(pq_path, "rb") as f:
            pq = f.read()
            f.close()

        with open(npq_path, "rb") as f:
            npq = f.read()
            f.close()

        return cls(pq, npq)

    def __init__(
        self, pqpk: Optional[bytes] = None, npqpk: Optional[bytes] = None
    ) -> None:
        """Builds a 1-1-26-910-ary Merkle Tree for a McEliece6960119 public key
        and a X25519 public key

        """
        super().__init__(mceliece6960119.PUBLICKEYBYTES, pqpk, npqpk)

    @staticmethod
    def get_children_range(depth: int, pos: int) -> tuple[int, int]:
        """Returns the range of position indexes of the children of the node at
        the given position.

        Excample:
        get_children_range(0, 0)
        (0, 1)

        get_children_range(1, 0)
        (0, 26)

        get_children_range(2, 0)
        (0, 36)

        get_children_range(2, 25)
        (1152, 1179)

        """

        if depth not in range(0, 3):
            raise ValueError

        elif depth == 0:
            if pos != 0:
                raise ValueError
            return (0, 1)

        elif depth == 1:
            if pos != 0:
                raise ValueError
            return (0, 26)

        else:  # depth == 2:
            if pos not in range(0, 26):
                raise ValueError
            return (pos * 36, min((pos + 1) * 36, 910))


if skem == mceliece6960119:
    PKTree: Any = _PKTree6960119

elif skem == mceliece8192128:
    PKTree = _PKTree8192128
