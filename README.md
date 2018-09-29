# Add homomorphic encryption test

This is a test for homomorphic encryption of adding op. The secp256k1 curve implemented
by ethereum is used in this test.

# Add public key

Just add x, y of public keys by curve op.

# Add priv key

It's a little different between add op of public keys. Since result of add
op should not bigger than N of curve. So private key used for test is smaller
than half of N of curve.