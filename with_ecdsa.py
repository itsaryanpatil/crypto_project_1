import random
from sympy import nextprime, mod_inverse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

def get_large_prime(bits=256):
    return nextprime(random.getrandbits(bits))

def get_generator(p):
    return random.randint(2, p - 1)

def bilinear_map(g1, g2, exponent, p):
    return pow(g1, exponent, p) * pow(g2, exponent, p) % p

def random_polynomial(degree, constant, p):
    coeffs = [random.randint(1, p - 1) for _ in range(degree)]
    coeffs.append(constant)
    return lambda x: sum(coeffs[i] * pow(x, i, p) for i in range(len(coeffs))) % p

def interpolation_coeff(i, S, p):
    num, denom = 1, 1
    for j in S:
        if j != i:
            num = (num * (-j)) % p
            denom = (denom * (i - j)) % p
    return (num * mod_inverse(denom, p)) % p

def select_d_elements(overlap, d):
    return list(overlap)[:d]

class FuzzyIBE:
    def __init__(self, universe_size, d, bits=256):
        self.p = get_large_prime(bits)
        self.g = get_generator(self.p)
        self.y = random.randint(1, self.p - 1)
        self.t = {i: random.randint(1, self.p - 1) for i in range(1, universe_size + 1)}
        self.T = {i: pow(self.g, self.t[i], self.p) for i in self.t}
        self.Y = bilinear_map(self.g, self.g, self.y, self.p)
        self.master_key = (self.y, self.t)
        self.d = d

        # ECDSA Keys for Signing & Verification
        self.signing_key = ec.generate_private_key(ec.SECP256R1())  # ECDSA Private Key
        self.verification_key = self.signing_key.public_key()  # ECDSA Public Key

    def keygen(self, identity):
        q = random_polynomial(degree=self.d - 1, constant=self.y, p=self.p)
        return {i: pow(self.g, q(i) * mod_inverse(self.t[i], self.p), self.p) for i in identity}

    def sign_message(self, message):
        """Sign the message using ECDSA"""
        message_bytes = str(message).encode()  # Convert message to bytes
        signature = self.signing_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_signature(self, signature, message):
        """Verify the message signature using ECDSA"""
        try:
            message_bytes = str(message).encode()
            self.verification_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            print("[VERIFY] Signature is valid.")
            return True
        except Exception:
            print("[VERIFY] Signature verification failed!")
            return False

    def encrypt(self, identity, message):
        """Encrypt the message after signing it"""
        signature = self.sign_message(message)  # Sign the message
        signed_message = (signature, message)  # Store (signature, message)
        
        s = random.randint(1, self.p - 1)
        E_prime = (message * pow(self.Y, s, self.p)) % self.p
        E_i = {i: pow(self.T[i], s, self.p) for i in identity}
        return identity, E_prime, E_i, s, signature  # Include signature in ciphertext

    def decrypt(self, private_key, ciphertext):
        """Decrypt the message and verify the signature"""
        identity, E_prime, E_i, s, signature = ciphertext
        overlap = set(private_key.keys()).intersection(identity)
        
        if len(overlap) < self.d:
            raise ValueError("Insufficient attribute match for decryption")
        
        S = select_d_elements(overlap, self.d)
        exponent = sum(interpolation_coeff(i, S, self.p) * pow(private_key[i], s, self.p) for i in S) % self.p
        message = (E_prime * mod_inverse(pow(self.Y, s, self.p), self.p)) % self.p
        
        # Verify signature
        if self.verify_signature(signature, message):
            return message  # If valid, return decrypted message
        else:
            raise ValueError("Signature verification failed!")

# Example usage
universe_size = 10
d = 3
ibe = FuzzyIBE(universe_size, d)
identity_A = {1, 2, 3, 4, 5}
identity_B = {3, 4, 5, 6, 7}
message = 42

print("\n[STEP] Generating Private Key for Identity A")
private_key_A = ibe.keygen(identity_A)

print("\n[STEP] Encrypting Message")
ciphertext = ibe.encrypt(identity_B, message)
print("Ciphertext:", ciphertext)

print("\n[STEP] Attempting Decryption")
try:
    decrypted_message = ibe.decrypt(private_key_A, ciphertext)
    print("[RESULT] Decrypted Message:", decrypted_message)
except ValueError as e:
    print("[ERROR] Decryption Failed:", e)