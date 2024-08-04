# Challenges

### Set 1: Basics
1. Convert hex to base64
2. Fixed XOR
3. Single-byte XOR cipher
4. Detect single-character XOR
5. Implement repeating-key XOR
6. Break repeating-key XOR
7. AES in ECB mode
8. Detect AES in ECB mode

### Set 2: Block Crypto
1. Implement PKCS#7 padding
2. Implement CBC mode
3. An ECB/CBC detection oracle
4. Byte-at-a-time ECB decryption (Simple)
5. ECB cut-and-paste
6. Byte-at-a-time ECB decryption (Harder)
7. PKCS#7 padding validation
8. CBC bitflipping attacks

### Set 3: Block & Stream Crypto
1. The CBC padding oracle
2. Implement CTR, the stream cipher mode
3. Break fixed-nonce CTR mode using substitutions
4. Break fixed-nonce CTR statistically
5. Implement the MT19937 Mersenne Twister RNG
6. Crack an MT19937 seed
7. Clone an MT19937 RNG from its output
8. Create the MT19937 stream cipher and break it

### Set 4: Stream Crypto & Randomness
1. Break "random access read/write" AES CTR
2. CTR bitflipping
3. Recover the key from CBC with IV=Key
4. Implement a SHA-1 keyed MAC
5. Break a SHA-1 keyed MAC using length extension
6. Break an MD4 keyed MAC using length extension
7. Implement and break HMAC-SHA1 with an artificial timing leak
8. Break HMAC-SHA1 with a slightly less artificial timing leak

### Set 5: Diffie-Hellman & Friends
1. Implement Diffie-Hellman
2. Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
3. Implement DH with negotiated groups, and break with malicious "g" parameters
4. Implement Secure Remote Password (SRP)
5. Break SRP with a zero key
6. Offline dictionary attack on simplified SRP
7. Implement RSA
8. Implement an E=3 RSA Broadcast attack

### Set 6: RSA and DSA
1. Implement unpadded message recovery oracle
2. Bleichenbacher's e=3 RSA Attack
3. DSA key recovery from nonce
4. DSA nonce recovery from repeated nonce
5. DSA parameter tampering
6. RSA parity oracle
7. Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
8. Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

### Set 7: Hashes
1. CBC-MAC Message Forgery
2. Hashing with CBC-MAC
3. Compression Ratio Side-Channel Attacks
4. Iterated Hash Function Multicollisions
5. Kelsey and Schneier's Expandable Messages
6. Kelsey and Kohno's Nostradamus Attack
7. MD4 Collisions
8. RC4 Single-Byte Biases

### Set 8: Abstract Algebra
1. Diffie-Hellman Revisited: Small Subgroup Confinement
2. Pollard's Method for Catching Kangaroos
3. Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks
4. Single-Coordinate Ladders and Insecure Twists
5. Duplicate-Signature Key Selection in ECDSA (and RSA)
6. Key-Recovery Attacks on ECDSA with Biased Nonces
7. Key-Recovery Attacks on GCM with Repeated Nonces
8. Key-Recovery Attacks on GCM with a Truncated MAC
9. Truncated-MAC GCM Revisited: Improving the Key-Recovery Attack via Ciphertext Length Extension
10. Exploiting Implementation Errors in Diffie-Hellman