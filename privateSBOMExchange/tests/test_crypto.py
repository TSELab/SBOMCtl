from petra.lib.crypto import Commitment

print("Creating commitment for byte string 0xdecafbad")

commit = Commitment(b'decafbad')

print("Got commitment: %s" % commit.value.hex())

print("Verification passed? %s" % str(commit.verify(b'decafbad')))

print("Testing verification of bad commitment opening 0xdeadbeef")

print("Verification passed? %s" % str(commit.verify(b'deadbeef')))
