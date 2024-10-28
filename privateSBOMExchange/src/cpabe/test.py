#!/usr/bin/env python3
import cpabe

POLICY = '"lol" or "what"'
GROUPS = ['lol', 'what']
SUBGROUPS = ['lol']
PLAINTEXT = """Sittin' in the mornin' sun
I'll be sittin' when the evenin' come
Watching the ships roll in
And then I watch 'em roll away again, yeah"""

# first, we encrypt and decrypt successfully
pk, mk = cpabe.cpabe_setup();
sk = cpabe.cpabe_keygen(pk, mk, GROUPS)
ct = cpabe.cpabe_encrypt(pk, POLICY, PLAINTEXT.encode("utf-8"))
pt = cpabe.cpabe_decrypt(sk, ct)
pt_text = "".join([chr(x) for x in pt])
assert pt_text == PLAINTEXT

# we test the delegation functionality as well
sk2=cpabe.cpabe_delegate(pk, sk, SUBGROUPS)
pt2 = cpabe.cpabe_decrypt(sk2, ct)
pt_text2 = "".join([chr(x) for x in pt])
assert pt_text == pt_text2
print(pt_text2)
