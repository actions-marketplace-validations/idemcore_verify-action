# Test vectors

`vectors_r2.json` is an official test vector copied unchanged from the public
[idemcore-python](https://github.com/idemcore/idemcore-python) repository. It is
signed with an ephemeral test key, not the production signing key, and is not a
live receipt. `keys-r2.json` is its public test key as a JWKS.

`log.txt` is the public token log that goes with it. `tampered_r2.json` is the
same receipt with `model_id` changed, so its signature fails. `audit.json` holds
the audit events, the signed daily root and the test key from the same public
test vectors.
