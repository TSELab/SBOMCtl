import unittest

from petra.crypto import Commitment


class TestComitment(unittest.TestCase):
    def test_end_to_end_commitment(self):

        commit = Commitment(b"decafbad")
        hexc = commit.to_hex()

        self.assertTrue(commit.verify(commit.salt, b"decafbad"))

        self.assertFalse(commit.verify(commit.salt, b"deadbeef"))

        recon_commit = Commitment.from_hex(hexc)

        self.assertTrue(recon_commit.verify(recon_commit.salt, b"decafbad"))
