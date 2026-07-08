# 🔐 Authenticated Key Exchange (Diffie-Hellman + Digital Signatures)

> **Goal:** Let Alice and Bob agree on a shared secret **without ever sending the secret itself** — and make sure they're *actually* talking to each other, not to an attacker in the middle.

---

## 📖 Table of Contents

- [The Big Idea (Paint Analogy)](#-the-big-idea-paint-analogy)
- [Core Concepts](#-core-concepts)
- [The Handshake (Step by Step)](#-the-handshake-step-by-step)
- [Why Plain Diffie-Hellman Isn't Enough](#️-why-plain-diffie-hellman-isnt-enough)
- [The Fix: Sign Your Keys](#️-the-fix-sign-your-keys)
- [Full Working Code](#-full-working-code-python)
- [Sample Output](#-sample-output)
- [Where This Is Used](#-where-this-is-used-in-the-real-world)
- [Mental Model Cheat Sheet](#-mental-model-cheat-sheet)

---

## 🎨 The Big Idea (Paint Analogy)

The classic way to understand Diffie-Hellman: **mixing paint**. It's easy to mix two
colors together, but nearly impossible to *un-mix* them back into the originals. That
one-way difficulty is what keeps the secret safe.

```
   PUBLIC (everyone, incl. Eve, sees this):  a common yellow  🟡

   ALICE                                             BOB
   ─────                                             ───
   secret: red   🔴                                  secret: blue  🔵
        │                                                 │
        │ mix with yellow                                 │ mix with yellow
        ▼                                                 ▼
   orange 🟠  ───────────  send over wire  ──────────▶  orange 🟠
   (Eve sees orange)                                  green 🟢  ◀── (Eve sees green)
        ▲                                                 │
        │ add own secret red 🔴                           │ add own secret blue 🔵
        ▼                                                 ▼
   yellow+blue+red  ═══  SAME MUDDY BROWN  ═══  yellow+red+blue
                         🟤 shared secret 🟤

   Eve has yellow, orange, and green — but NOT red or blue, so she can't make brown.
   Un-mixing paint (extracting the secret color) is the hard part she can't do.
```

**The magic:** Alice and Bob end up with the **same muddy brown**, but that color was
never transmitted. Eve saw every message on the wire and still can't reproduce it.

---

## 🧠 Core Concepts

**The core idea**

> They exchange **PUBLIC keys only**. Each side combines its own **PRIVATE key** with
> the other's **PUBLIC key** → both independently arrive at the **SAME secret**.

**The magic property**

```
Alice_private × Bob_public   =  shared_secret
Bob_private   × Alice_public =  shared_secret
```

**The important insight**

> The secret is **NEVER transmitted**. It is independently computed on both sides.

| Piece            | Role                                                        |
| ---------------- | ----------------------------------------------------------- |
| **Public keys**  | Open conversation — safe to broadcast to the whole world    |
| **Private keys** | The secret ingredient — never leaves your device            |
| **Math**         | Guarantees both sides land on the exact same shared secret  |

---

## 🤝 The Handshake (Step by Step)

Real systems layer **two key types**:

- **Ed25519** — long-term *identity* keys, used to **sign** (prove who you are). Think of it as a digital certificate.
- **X25519** — throwaway *ephemeral* keys, generated fresh per session, used for the actual **Diffie-Hellman** key agreement.

```
ALICE'S DEVICE                                                    BOB'S DEVICE
=============================                                   =============================
[Long-Term Ed25519 Identity]                                    [Long-Term Ed25519 Identity]
  └── Alice_Identity_Pub ─────────── (Exchanged Ahead of Time) ─────────> Knows Alice_Identity_Pub

1. Generate temporary X25519                                    1. Generate temporary X25519
   Ephemeral Key Pair                                              Ephemeral Key Pair
2. Sign Ephemeral Public Key:                                   2. Sign Ephemeral Public Key:
   Sig = Sign(Alice_Eph_Pub)                                       Sig = Sign(Bob_Eph_Pub)

         │                                                                │
         │─────── Send: [Alice_Eph_Pub] + [Alice_Sig] ───────>            │
         │                                                                │
         │                        <─── Send: [Bob_Eph_Pub] + [Bob_Sig] ───│
         ▼                                                                ▼

3. VERIFY Bob's signature using                                 3. VERIFY Alice's signature using
   his known Identity Key.                                         her known Identity Key.
   (Fails if Eve swapped keys! ❌)                                 (Fails if Eve swapped keys! ❌)

4. Compute Raw Shared Secret                                    4. Compute Raw Shared Secret
5. Refine key using HKDF                                        5. Refine key using HKDF
         │                                                                │
         ▼                                                                ▼
   [32-Byte AES Session Key]  <======= SAME SECRET KEY =======>    [32-Byte AES Session Key]
         │                                                                │
         ▼                                                                ▼
   [ AES-GCM ENCRYPTION ]                                           [ AES-GCM DECRYPTION ]
```

**What each step buys you:**

1. **Ephemeral keys** → *forward secrecy*. Even if a long-term key leaks later, past sessions stay safe.
2. **Signing the ephemeral key** → binds a throwaway key to a real identity.
3. **Verifying the signature** → blocks the man-in-the-middle (see below).
4. **Diffie-Hellman exchange** → produces the raw shared secret.
5. **HKDF** → stretches/refines the raw secret into a clean, uniform 32-byte AES key.

---

## ⚠️ Why Plain Diffie-Hellman Isn't Enough

Diffie-Hellman by itself proves **nobody can read the secret** — but it does **not**
prove **who you're talking to**. That gap is the **man-in-the-middle (MITM) attack**.

```
Alice  ↔  Eve  ↔  Bob

Alice thinks she talks to Bob.
Bob   thinks he talks to Alice.
But both are actually talking to Eve.
```

Eve runs *two* separate key exchanges — one with Alice, one with Bob — and silently
relays (and reads) everything in between. Neither side notices, because plain DH never
asked "are you really who you say you are?"

---

## 🛡️ The Fix: Sign Your Keys

```
DH  +  Digital Signatures  =  Authenticated Key Exchange
```

By signing each ephemeral public key with a **long-term identity key** that the other
party already trusts, Eve can no longer impersonate anyone. If she swaps in her own key,
the signature check fails and the handshake aborts.

---

## 💻 Full Working Code (Python)

> Requires the [`cryptography`](https://cryptography.io/) library: `pip install cryptography`

### Imports

```python
import os
import sys
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  # Digital Certificate
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey     # DH
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
```

### Section 1 — Global Helpers & Data Structures

```python
# ============================================================================
# SECTION 1: GLOBAL HELPERS & DATA STRUCTURES
# ============================================================================

def get_raw_public_bytes(x25519_pub: X25519PublicKey) -> bytes:
    """Serialize an X25519 public key into raw bytes so it can be sent over the wire.

    Args:
        x25519_pub (X25519PublicKey): The ephemeral DH public key object to flatten.

    Returns:
        bytes: Exactly 32 raw bytes (no PEM/DER wrapper). This is what the peer
            re-imports on the other end via ``X25519PublicKey.from_public_bytes()``.

    Example:
        >>> priv = X25519PrivateKey.generate()
        >>> raw = get_raw_public_bytes(priv.public_key())
        >>> len(raw)
        32
        >>> raw.hex()
        '8f2a...c1'   # 64 hex chars = 32 bytes
    """
    return x25519_pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )

@dataclass
class EncryptedEnvelope:
    """The data package that travels over the untrusted network wire.

    This is the *only* thing an eavesdropper (Eve) ever sees. None of these
    fields reveal the plaintext or the session key.

    Fields:
        sender_name (str): Who sent it, e.g. ``"Alice"``. Also fed into AES-GCM
            as Associated Data (AAD), so renaming the sender breaks decryption.
        nonce (bytes): A fresh 12-byte random number, unique per message.
            Prevents two identical messages from producing identical ciphertext.
            Example: ``b'\\x93\\x81\\xa9...'`` → ``"9381a943a237d636966b7471"`` in hex.
        ciphertext (bytes): The scrambled message **plus** a 16-byte GCM
            authentication tag appended at the end. Flipping any bit here makes
            decryption raise ``InvalidTag``.

    Example:
        EncryptedEnvelope(
            sender_name="Alice",
            nonce=b'\\x93\\x81...',                 # 12 bytes
            ciphertext=b'\\xeb\\xa7\\x6f...\\x_tag_' # message + 16-byte tag
        )
    """
    sender_name: str
    nonce: bytes
    ciphertext: bytes  # Contains scrambled text + the GCM authentication tag
```

### Section 2 — The User Entity (Alice / Bob)

```python
# ============================================================================
# SECTION 2: THE USER ENTITY (ALICE / BOB)
# ============================================================================

class SecureUser:
    def __init__(self, name: str):
        """Create a participant (Alice, Bob, or Eve) and generate their keys.

        Sets up two independent key pairs on the "device":

        Instance attributes:
            name (str): Human label, e.g. ``"Alice"``.
            identity_private (Ed25519PrivateKey): LONG-TERM secret. Signs your
                ephemeral keys to prove identity. Never leaves the device, never expires.
            identity_public (Ed25519PublicKey): LONG-TERM public. Shared with peers
                ahead of time so they can verify your signatures. Safe to publish.
            _ephemeral_private (X25519PrivateKey | None): PER-SESSION DH secret.
                Starts as ``None``; created in ``create_handshake_package()``.
                Discarded after the session → gives forward secrecy.
            session_key (bytes | None): The final 32-byte AES key. Starts ``None``;
                filled in by ``process_handshake_package()``. Identical on both peers.

        Args:
            name (str): The display name for this user.
        """
        self.name = name

        # 1. Long-Term Identity Keys (Ed25519) - Used for signing/verifying identity (Digital Certificate)
        self.identity_private = Ed25519PrivateKey.generate()
        self.identity_public = self.identity_private.public_key()

        # 2. Ephemeral Session Keys (X25519) - Created fresh per handshake (DH)
        self._ephemeral_private = None
        self.session_key = None

    def create_handshake_package(self):
        """Step A: Generate a temporary DH key and sign it to block attackers (Eve).

        Called once per session, *before* talking to the peer. The returned pair
        is what you transmit over the (untrusted) network.

        Returns:
            tuple[bytes, bytes]: A 2-tuple of ``(ephemeral_public_bytes, signature)``:
                - ephemeral_public_bytes (bytes): 32 raw bytes of your fresh X25519
                  public key. This is the "half" the peer needs for Diffie-Hellman.
                - signature (bytes): 64-byte Ed25519 signature over those exact
                  bytes, made with your long-term identity key. This is the tamper-proof
                  "wax seal" proving the ephemeral key is really yours.

        Example:
            >>> alice = SecureUser("Alice")
            >>> eph_pub, sig = alice.create_handshake_package()
            >>> len(eph_pub), len(sig)
            (32, 64)
        """
        self._ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = self._ephemeral_private.public_key()
        ephemeral_public_bytes = get_raw_public_bytes(ephemeral_public)

        # Securely stamp our temporary key using our permanent identity signature
        signature = self.identity_private.sign(ephemeral_public_bytes)
        return ephemeral_public_bytes, signature

    def process_handshake_package(self, peer_name: str, peer_identity_pub: Ed25519PublicKey, peer_eph_bytes: bytes, peer_sig: bytes):
        """Step B: Verify the peer's signature, run DH, and derive the AES session key.

        This is where authentication + key agreement happen together. On success,
        ``self.session_key`` is populated and will match the peer's session key exactly.

        Args:
            peer_name (str): The peer's label, only used for readable log messages,
                e.g. ``"Bob"``.
            peer_identity_pub (Ed25519PublicKey): The peer's LONG-TERM public identity
                key, which you already trust (exchanged ahead of time). Used to check
                the signature. If Eve sends her own key here instead, the check fails.
            peer_eph_bytes (bytes): The peer's 32-byte ephemeral X25519 public key
                (the ``ephemeral_public_bytes`` from their ``create_handshake_package``).
            peer_sig (bytes): The peer's 64-byte signature over ``peer_eph_bytes``.

        Returns:
            None: Nothing is returned. The result is stored as a side effect in
                ``self.session_key`` (32 bytes, e.g. ``b'\\x1f\\x9c...'``).

        Raises:
            InvalidSignature: If ``peer_sig`` was not produced by ``peer_identity_pub``
                over ``peer_eph_bytes`` — i.e. someone tampered with or forged the key.
                The handshake is aborted and no session key is set.

        Example:
            >>> alice.process_handshake_package("Bob", bob.identity_public,
            ...                                 bob_eph_bytes, bob_sig)
            >>> len(alice.session_key)
            32
        """

        # 1. AUTHENTICITY CHECK: Verify that the peer's permanent key signed their temporary key
        try:
            peer_identity_pub.verify(peer_sig, peer_eph_bytes)
            print(f"   🛡️ [{self.name}] Verification Success: This key genuinely belongs to {peer_name}!")
        except InvalidSignature:
            print(f"   🚨 [{self.name}] SECURITY ALERT: Signature mismatch! Someone tried to hijack the key!")
            raise InvalidSignature("Handshake aborted: Untrusted key signature detected.")

        # 2. KEY AGREEMENT: Compute the raw Diffie-Hellman secret
        peer_ephemeral_public = X25519PublicKey.from_public_bytes(peer_eph_bytes)
        raw_shared_secret = self._ephemeral_private.exchange(peer_ephemeral_public)

        # 3. KEY REFINEMENT: Extract a balanced, secure 32-byte AES key using HKDF
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"e2ee-secure-session-v1",
        ).derive(raw_shared_secret)

    # ============================================================================
    # SECTION 3: SYMMETRIC MESSAGING LAYER (AES-256-GCM)
    # ============================================================================

    def encrypt_message(self, plaintext: str) -> EncryptedEnvelope:
        """Encrypt a message with the established session key, ready to send.

        Args:
            plaintext (str): The human-readable message to protect, e.g.
                ``"Hey Bob, the password is 4815."``.

        Returns:
            EncryptedEnvelope: A sealed package safe to send over the network:
                - sender_name = ``self.name`` (also bound in as AAD)
                - nonce = fresh 12 random bytes
                - ciphertext = scrambled bytes + 16-byte auth tag
            To an eavesdropper this is pure gibberish.

        Raises:
            ValueError: If no session key exists yet (handshake not run).

        Example:
            >>> env = alice.encrypt_message("meet at the lab")
            >>> env.sender_name
            'Alice'
            >>> env.ciphertext.hex()[:16]
            'eba76fde14eb5e73'   # unreadable without the key
        """
        if not self.session_key:
            raise ValueError("No secure session established. Run handshake first.")

        aesgcm = AESGCM(self.session_key)
        nonce = os.urandom(12)  # 12-byte initialization vector, must be unique every time

        # The sender's name is passed as Associated Data (AAD) to prevent structural tampering
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), self.name.encode())
        return EncryptedEnvelope(sender_name=self.name, nonce=nonce, ciphertext=ciphertext)

    def decrypt_message(self, envelope: EncryptedEnvelope) -> str:
        """Decrypt an envelope and verify it wasn't tampered with in transit.

        Args:
            envelope (EncryptedEnvelope): The package received from the peer.
                Its ``nonce``, ``ciphertext``, and ``sender_name`` (used as AAD)
                must all be intact, and it must have been encrypted with the
                matching session key.

        Returns:
            str: The original plaintext, e.g. ``"Hey Bob, the password is 4815."``.

        Raises:
            ValueError: If no session key exists yet (handshake not run).
            cryptography.exceptions.InvalidTag: If even one bit of the ciphertext,
                nonce, or sender_name was altered, OR the wrong key is used. The
                message is rejected rather than returning corrupted text.

        Example:
            >>> bob.decrypt_message(env)
            'meet at the lab'
        """
        if not self.session_key:
            raise ValueError("No secure session established. Run handshake first.")

        aesgcm = AESGCM(self.session_key)

        # Will raise an InvalidTag exception if data was modified or key is wrong
        plaintext_bytes = aesgcm.decrypt(envelope.nonce, envelope.ciphertext, envelope.sender_name.encode())
        return plaintext_bytes.decode()
```

### Section 4 — Network Execution Simulation

```python
# ============================================================================
# SECTION 4: NETWORK EXECUTION SIMULATION
# ============================================================================

if __name__ == "__main__":
    print("=== STARTING SIMULATION: AUTHENTICATED KEY EXCHANGE ===")

    # Initialize devices
    alice = SecureUser("Alice")
    bob = SecureUser("Bob")

    # PHASE 1: The Handshake
    print("\n[Step 1] Alice and Bob pack and sign their public keys...")
    alice_eph_bytes, alice_sig = alice.create_handshake_package()
    bob_eph_bytes, bob_sig = bob.create_handshake_package()

    print("\n[Step 2] Processing keys across devices (Verifying Seals)...")
    # Alice processes Bob's key package
    alice.process_handshake_package("Bob", bob.identity_public, bob_eph_bytes, bob_sig)
    # Bob processes Alice's key package
    bob.process_handshake_package("Alice", alice.identity_public, alice_eph_bytes, alice_sig)

    # Verify matching keys
    print(f"\nKeys match perfectly on both devices? {alice.session_key == bob.session_key}  ✅")

    # PHASE 2: Secure Chatting
    print("\n=== STARTING SIMULATION: ENCRYPTED MESSAGING ===")

    # Alice sends a message
    msg_text = "Hey Bob, meet me at the lab. The password to the door is 4815."
    print(f"\n1. Alice Types: '{msg_text}'")
    envelope = alice.encrypt_message(msg_text)

    print(f"2. Intercepted data on network wire:")
    print(f"   Sender    : {envelope.sender_name}")
    print(f"   Nonce     : {envelope.nonce.hex()}")
    print(f"   Ciphertext: {envelope.ciphertext.hex()[:40]}... [GIBBERISH]")

    # Bob decrypts the incoming envelope
    recovered_text = bob.decrypt_message(envelope)
    print(f"3. Bob Decrypts and Reads: '{recovered_text}' ✅")

    # PHASE 3: Attacker Simulation (Eve)
    print("\n=== STARTING SIMULATION: ATTACK SCENARIOS ===")

    print("\n[Attack A] Eve tries to modify message traffic in transit...")
    tampered_bytes = bytearray(envelope.ciphertext)
    tampered_bytes[0] ^= 0x01  # Flip a single bit
    tampered_envelope = EncryptedEnvelope(envelope.sender_name, envelope.nonce, bytes(tampered_bytes))

    try:
        bob.decrypt_message(tampered_envelope)
    except Exception as e:
        print(f"   Custom Decryption Output ──► {type(e).__name__}: Tampering detected! Content discarded. ✅")

    print("\n[Attack B] Eve tries to execute a MITM attack by generating a malicious key...")
    eve = SecureUser("Eve")
    eve_eph_bytes, _ = eve.create_handshake_package()

    # Eve tries to forge Alice's signature over Eve's key package
    forged_sig = eve.identity_private.sign(eve_eph_bytes)  # Signed by Eve, NOT Alice

    try:
        bob.process_handshake_package("Alice", alice.identity_public, eve_eph_bytes, forged_sig)
    except InvalidSignature:
        print("   Custom Handshake Output   ──► Attack Blocked! Bob recognized Eve's forged signature stamp. ✅")
```

---

## 📟 Sample Output

```
=== STARTING SIMULATION: AUTHENTICATED KEY EXCHANGE ===

[Step 1] Alice and Bob pack and sign their public keys...

[Step 2] Processing keys across devices (Verifying Seals)...
   🛡️ [Alice] Verification Success: This key genuinely belongs to Bob!
   🛡️ [Bob] Verification Success: This key genuinely belongs to Alice!

Keys match perfectly on both devices? True  ✅

=== STARTING SIMULATION: ENCRYPTED MESSAGING ===

1. Alice Types: 'Hey Bob, meet me at the lab. The password to the door is 4815.'
2. Intercepted data on network wire:
   Sender    : Alice
   Nonce     : 9381a943a237d636966b7471
   Ciphertext: eba76fde14eb5e73a78c537de1d71031f75b6847... [GIBBERISH]
3. Bob Decrypts and Reads: 'Hey Bob, meet me at the lab. The password to the door is 4815.' ✅

=== STARTING SIMULATION: ATTACK SCENARIOS ===

[Attack A] Eve tries to modify message traffic in transit...
   Custom Decryption Output ──► InvalidTag: Tampering detected! Content discarded. ✅

[Attack B] Eve tries to execute a MITM attack by generating a malicious key...
   🚨 [Bob] SECURITY ALERT: Signature mismatch! Someone tried to hijack the key!
   Custom Handshake Output   ──► Attack Blocked! Bob recognized Eve's forged signature stamp. ✅
```

**Two attacks, both defeated:**

- **Attack A (Tampering):** Eve flips a single bit in the ciphertext. AES-GCM's authentication tag catches it → `InvalidTag`.
- **Attack B (MITM):** Eve forges a signature with her own identity key. Bob checks it against *Alice's* known key → mismatch, handshake aborts.

---

## 🌍 Where This Is Used in the Real World

```
✔ HTTPS (TLS 1.3)
✔ WhatsApp / Signal
✔ Secure APIs
✔ SSH
✔ VPNs (WireGuard uses exactly X25519)
```

---

## 🎯 Mental Model Cheat Sheet

**One-line intuition**

> Diffie-Hellman = agree on a secret over a public channel **without ever sending it**.

**Final mental model**

```
Public keys  = open conversation
Private keys = secret ingredient
Math         = ensures both sides end up with the same secret
Signatures   = prove you're talking to the right person
```

| Component        | Algorithm      | Job                                            |
| ---------------- | -------------- | ---------------------------------------------- |
| Identity keys    | Ed25519        | Sign & verify — *who are you?*                 |
| Ephemeral keys   | X25519         | Diffie-Hellman key agreement — *shared secret* |
| Key derivation   | HKDF-SHA256    | Refine raw secret → clean 32-byte AES key      |
| Message encryption | AES-256-GCM  | Confidentiality **+** tamper detection         |

---

<sub>📚 Educational demo. For production, use a vetted protocol implementation (TLS, the Signal/Noise protocol frameworks) rather than hand-rolled crypto.</sub>
