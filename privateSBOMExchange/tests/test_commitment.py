from petra.crypto import Commitment

print("Creating commitment for byte string 0xdecafbad")

commit = Commitment(b'decafbad')
hexc = commit.to_hex()

print("Got commitment: (%s, %s)" % (hexc[0], hexc[1]))

print("Verification passed? %s" % str(commit.verify(commit.salt, b'decafbad')))

print("Testing verification of bad commitment opening 0xdeadbeef")

print("Verification passed? %s" % str(commit.verify(commit.salt, b'deadbeef')))

print("Testing commitment reconstruction from hex tuple")

recon_commit = Commitment.from_hex(hexc)

print("Verification passed? %s" % str(recon_commit.verify(recon_commit.salt, b'decafbad')))
