# f2chat - True FHE Routing with Sheaf-Wreath Attention

**Status: Phase 2 In Progress - FHE Infrastructure Layer**

## 🎯 Mission

Build a **truly metadata-private messaging system** where the server performs blind algebraic routing on **fully encrypted polynomials**. No plaintext polynomial IDs, no plaintext mailbox addresses - the server sees **only encrypted blobs** and computes homomorphically.

## 🔑 Key Innovation: Blind Routing

```
❌ What We DON'T Want (Phase 1 - Current State):
   Alice → Server: {plaintext_polynomial_id: "9902", message}
   Server sees: Polynomial ID 9902 goes to mailbox 15072
   ❌ Server knows metadata!

✅ What We DO Want (Phase 2+ - Target State):
   Alice → Server: {Enc(P_alice), Enc(P_bob), Enc(message)}
   Server sees: Three encrypted blobs
   Server computes: Routing on encrypted data using wreath-sheaf algebra
   Server stores: Enc(message) at Enc(mailbox_location)
   ✅ Server learns NOTHING!
```

---

## 📊 Development Status

### ✅ Phase 1: Plaintext Polynomial Routing (COMPLETE)

**Status**: 32 tests passing, 1,340 lines of code

- ✅ Polynomial ring operations (Z_p[x]/(x^n + 1))
- ✅ Polynomial identities (device-held, unlinkable)
- ✅ Algebraic routing (polynomial encoding/decoding)
- ✅ Sheaf router (Algorithm 2.1 from paper)
- ✅ Alice → Bob integration test
- ✅ Wreath product attention (character projections)

**Limitation**: Server sees plaintext polynomial IDs - not true FHE!

### 🚧 Phase 2: FHE Infrastructure (IN PROGRESS)

**Status**: 9 FHE tests passing (stubs), infrastructure in place

#### ✅ Completed (2025-11-11):

- ✅ OpenFHE dependency added to MODULE.bazel
- ✅ FHEContext wrapper (`lib/crypto/fhe_context.{h,cc}`)
- ✅ EncryptedPolynomial class (`lib/crypto/encrypted_polynomial.{h,cc}`)
- ✅ Homomorphic operations (Add, Subtract, Rotate, MultiplyScalar)
- ✅ Test structure for FHE operations
- ✅ Build system configured

#### 🔨 TODO - OpenFHE Integration:

```cpp
// lib/crypto/fhe_context.cc - Lines 35-62
// Current: UnimplementedError stubs
// Needed: Replace with actual OpenFHE BGV implementation

absl::StatusOr<FHEContext> FHEContext::Create() {
  // TODO: Initialize OpenFHE crypto context
  // CCParams<CryptoContextBGVRNS> parameters;
  // parameters.SetMultiplicativeDepth(0);  // Depth-0 only!
  // parameters.SetPlaintextModulus(RingParams::kModulus);
  // parameters.SetRingDim(RingParams::kDegree);
  // CryptoContext cc = GenCryptoContext(parameters);
  // cc->Enable(PKE);
  // cc->Enable(KEYSWITCH);
  // cc->Enable(LEVELEDSHE);
  // return FHEContext(cc);
}
```

**Files to implement**:

1. `lib/crypto/fhe_context.cc` - Fill in OpenFHE calls
2. `lib/crypto/encrypted_polynomial.cc:ProjectToCharacter()` - Homomorphic DFT
3. Update `third_party/openfhe.BUILD` for actual OpenFHE build

### 📋 Phase 3: Encrypted Mailbox Addressing (TODO)

**Goal**: Server stores messages at encrypted mailbox locations

```cpp
// lib/network/encrypted_mailbox.{h,cc} - TO BE CREATED
class EncryptedMailbox {
  // Compute mailbox ID from encrypted polynomial
  static EncryptedPolynomial ComputeMailboxID_FHE(
      const EncryptedPolynomial& enc_dest_poly,
      const FHEContext& fhe_ctx);

  // Server's blind storage:
  // map<EncryptedPolynomial, vector<EncryptedPolynomial>> mailboxes;
  // Server cannot decrypt keys or values!
};
```

**Tasks**:

- [ ] Create `lib/network/encrypted_mailbox.{h,cc}`
- [ ] Implement homomorphic mailbox ID computation
- [ ] Update server to use encrypted storage
- [ ] Test: Server cannot determine which mailbox

### 📋 Phase 4: Homomorphic Routing (TODO)

**Goal**: Apply wreath-sheaf routing on encrypted polynomials

```cpp
// lib/crypto/routing_polynomial.h - NEW METHOD
class RoutingPolynomial {
  // Current: EncodeRoute() on plaintext
  // Needed: HomomorphicEncodeRoute() on encrypted data

  static EncryptedPolynomial HomomorphicEncodeRoute(
      const EncryptedPolynomial& enc_source,
      const EncryptedPolynomial& enc_destination,
      const EncryptedPolynomial& enc_message,
      const FHEContext& fhe_ctx);
};
```

**Tasks**:

- [ ] Implement `HomomorphicEncodeRoute()`
- [ ] Update `lib/network/patch.{h,cc}` for encrypted character projections
- [ ] Update `lib/network/sheaf_router.{h,cc}` for encrypted routing
- [ ] Test: Decrypt(ServerRoute(Enc(msg))) == msg

### 📋 Phase 5: Private Information Retrieval (TODO)

**Goal**: Bob retrieves messages without revealing his mailbox

```cpp
// lib/network/pir_client.{h,cc} - TO BE CREATED
// lib/network/pir_server.{h,cc} - TO BE CREATED

class PIRClient {
  // Generate oblivious query for mailbox
  PIRQuery GenerateQuery(
      const EncryptedPolynomial& my_enc_mailbox_id);
};

class PIRServer {
  // Process query without learning mailbox ID
  PIRResponse ProcessQuery(
      const PIRQuery& query,
      const EncryptedMailboxStorage& storage);
};
```

**Options**:

1. Integrate SealPIR (Microsoft Research, BFV-based)
2. Use SimplePIR (lattice-based, might be lighter)
3. Implement custom PIR using OpenFHE primitives

**Tasks**:

- [ ] Research: SealPIR vs SimplePIR vs custom
- [ ] Add PIR dependency to MODULE.bazel
- [ ] Implement PIR client/server
- [ ] Test: Server learns nothing about query

### 📋 Phase 6: End-to-End Integration (TODO)

**Goal**: Full Alice → Bob flow with zero server knowledge

```cpp
// test/integration/alice_to_bob_fhe_test.cc - TO BE CREATED

TEST(AliceToBobFHETest, TrueBlindRouting) {
  // 1. Alice and Bob generate FHE key pairs
  // 2. Alice encrypts: Enc(P_alice), Enc(P_bob), Enc("Hello")
  // 3. Server routes: HomomorphicEncodeRoute(...)
  // 4. Server stores: At encrypted mailbox location
  // 5. Bob queries: Via PIR (server doesn't know which mailbox)
  // 6. Bob decrypts: Gets "Hello"
  // 7. VERIFY: Server never decrypted anything!
}
```

**Success Criteria**:

- ✅ Server never calls Decrypt()
- ✅ Server never sees plaintext polynomial IDs
- ✅ Server never sees plaintext mailbox IDs
- ✅ All routing operations are depth-0 (no bootstrapping!)
- ✅ Cohomological obstruction = 0 (routing still perfect!)

---

## 🏗️ Architecture

### Current (Phase 1 - Plaintext Routing)

```
Alice Device:
├─ Real ID: "alice@example.com" (never sent)
├─ Polynomial ID: P_alice = [9902, ...] (PLAINTEXT - ❌ Server sees this!)
└─ Message: M = [72, 101, 108, 108, 111] ("Hello")

Server:
├─ Sees: P_alice, P_bob (plaintext polynomial IDs) ❌
├─ Routes: R = M + P_bob (plaintext algebra)
└─ Stores: At plaintext mailbox location ❌

Bob Device:
├─ Retrieves: Routed polynomial R
└─ Decrypts: M = R - P_bob
```

### Target (Phase 2+ - True FHE Routing)

```
Alice Device:
├─ Real ID: "alice@example.com" (never sent)
├─ FHE Keys: (pk_alice, sk_alice)
├─ Encrypts:
│   ├─ Enc(P_alice) using pk_alice
│   ├─ Enc(P_bob) using pk_bob (Bob's public key)
│   └─ Enc(M) using pk_bob
└─ Sends: {Enc(P_alice), Enc(P_bob), Enc(M)} ✅

Server (Blind Computation):
├─ Sees: Three encrypted blobs (cannot decrypt!) ✅
├─ Computes: Enc(R) = Enc(M) + Enc(P_bob) (homomorphically!)
├─ Computes: Enc(mailbox_id) = f(Enc(P_bob))
└─ Stores: Enc(R) at encrypted location ✅

Bob Device:
├─ Generates: PIR query for Enc(my_mailbox_id)
├─ Receives: Enc(R) (via PIR, server doesn't know which mailbox!) ✅
├─ Decrypts: M = Decrypt(Enc(R), sk_bob)
└─ Gets: "Hello" ✅
```

---

## 📁 File Structure

### Existing Files (Phase 1)

```
lib/crypto/
├── polynomial.{h,cc}              # Ring operations (Z_p[x]/(x^n+1))
├── polynomial_params.h             # SafeParams/MediumParams/ProductionParams
├── polynomial_identity.{h,cc}      # Device-held identities
└── routing_polynomial.{h,cc}       # Plaintext routing (Phase 1)

lib/network/
├── patch.{h,cc}                    # Network regions (wreath product)
├── gluing.{h,cc}                   # Boundary constraints (sheaf gluing)
└── sheaf_router.{h,cc}             # Algorithm 2.1 (unified sheaf learner)

test/
├── crypto/
│   ├── polynomial_test.cc          # 15 tests ✅
│   ├── polynomial_identity_test.cc # 12 tests ✅
│   └── encrypted_polynomial_test.cc # 9 tests ✅ (stubs)
└── integration/
    ├── simple_routing_test.cc      # 3 tests ✅
    └── alice_to_bob_test.cc        # 2 tests ✅ (plaintext routing)
```

### New Files (Phase 2+)

```
lib/crypto/
├── fhe_context.{h,cc}              # ✅ CREATED - OpenFHE wrapper (stubs)
└── encrypted_polynomial.{h,cc}     # ✅ CREATED - FHE polynomial (stubs)

lib/network/                        # 📋 TODO
├── encrypted_mailbox.{h,cc}        # Blind mailbox addressing
├── pir_client.{h,cc}               # PIR query generation
└── pir_server.{h,cc}               # PIR response (blind)

test/integration/                   # 📋 TODO
├── alice_to_bob_fhe_test.cc        # End-to-end FHE routing
└── privacy_analysis_test.cc        # Verify server learns nothing

third_party/
└── openfhe.BUILD                   # ✅ CREATED - OpenFHE build config
```

---

## 🚀 Quick Start (Current State)

### Build & Test (Phase 1 - Plaintext)

```bash
# Build all libraries
bazel build //lib/...

# Run all tests (32 passing)
bazel test //test/...

# Run Alice→Bob demo (plaintext routing)
bazel test //test/integration:alice_to_bob_test --test_output=all
```

### Test FHE Infrastructure (Phase 2 - Stubs)

```bash
# Test encrypted polynomial (9 tests - all return UnimplementedError)
bazel test //test/crypto:encrypted_polynomial_test --test_output=all

# Expected output: All tests pass (they verify UnimplementedError is returned)
```

---

## 🔬 Research Foundation

This project implements:

> **"An Algebraic Theory of Learnability: Solving Diverse Problems with a Unified Sheaf-Wreath Attention"**
> bon-cdp (shakilflynn@gmail.com), November 2025: https://github.com/bon-cdp/notes/blob/main/c.pdf

### Key Theoretical Components

**Wreath Product** (Position-Dependent Routing):

- Network positions have character distributions (DFT basis)
- Routing weights: `w[position][character]`
- Learned via closed-form solve: `w* = (A^H A)^{-1} A^H b` (Theorem 2.1)

**Sheaf** (Global Consistency):

- Network divided into patches (geographic regions)
- Each patch has local routing algebra
- Gluing constraints ensure message delivery
- Zero cohomological obstruction = guaranteed delivery

**FHE Application** (Novel Contribution):

- Server applies wreath-sheaf routing to **encrypted polynomials**
- Position-dependent weights applied homomorphically
- Character projections computed via homomorphic DFT
- Depth-0 operations only (no bootstrapping!)

---

## 🎯 Next Steps for Engineers

### 🔥 IMMEDIATE (This Week):

1. **Implement OpenFHE Integration** (`lib/crypto/fhe_context.cc`)

   - Replace UnimplementedError stubs with OpenFHE BGV calls
   - File: Lines 35-180
   - Estimated: 4-6 hours

2. **Implement Homomorphic Character Projection** (`lib/crypto/encrypted_polynomial.cc`)

   - ProjectToCharacter() - Line 96
   - Homomorphic DFT on encrypted polynomials
   - Estimated: 6-8 hours

3. **Verify Depth-0 Operations**
   - Audit all operations for multiplicative depth
   - Ensure no bootstrapping needed
   - Estimated: 2 hours

### 📅 SHORT TERM (Next 2 Weeks):

1. **Encrypted Mailbox Addressing** (Phase 3)

   - Create `lib/network/encrypted_mailbox.{h,cc}`
   - Homomorphic mailbox ID computation
   - Server-side blind storage
   - Estimated: 3-4 days

2. **Homomorphic Routing** (Phase 4)

   - Implement `HomomorphicEncodeRoute()`
   - Update patch/sheaf router for encrypted data
   - Estimated: 4-5 days

3. **PIR Integration** (Phase 5)
   - Research: SealPIR vs SimplePIR
   - Implement client/server
   - Estimated: 5-7 days

### 🎯 MILESTONE (End of Month):

- ✅ Full Alice → Bob FHE routing test passing
- ✅ Server performs zero decryptions
- ✅ Depth-0 operations verified
- ✅ Ready for Cloudflare Workers deployment

---

## 📚 Resources for Engineers

### OpenFHE Documentation

- **Main docs**: https://openfhe-development.readthedocs.io/
- **BGV examples**: `openfhe-development/src/pke/examples/`
- **API reference**: https://openfhe-development.readthedocs.io/en/latest/api.html

### Key Papers

1. OpenFHE library paper: https://eprint.iacr.org/2022/915.pdf
2. SealPIR: https://github.com/microsoft/SealPIR
3. BGV scheme: https://eprint.iacr.org/2011/277.pdf
4. **[Prerequisite Reading List](docs/reading_list.md)**: Essential reading for new contributors.

### Our Theory Paper

- See: `docs/sheaf_wreath_theory.pdf` (LaTeX source included)
- Key insight: Optimization replaced by algebra when problem has right symmetry

---

## 🐛 Known Issues & Limitations

### Phase 1 (Plaintext):

- ❌ Server sees plaintext polynomial IDs (not true metadata privacy)
- ❌ No actual encryption (just "unlinkable" pseudonyms)
- ✅ But: Routing algebra is correct (ready for FHE!)

### Phase 2 (Current):

- ⚠️ OpenFHE integration incomplete (stubs return UnimplementedError)
- ⚠️ Homomorphic character projection not implemented
- ⚠️ No encrypted mailbox addressing yet
- ✅ But: Infrastructure is in place!

---

## 📞 Contact

- **Author**: bon-cdp
- **Email**: shakilflynn@gmail.com
- **GitHub**: https://github.com/bon-cdp/f2chat

---

## 📄 License

Apache 2.0 - See LICENSE

---

## 🙏 Acknowledgments

This project builds on:

- OpenFHE team for the incredible FHE library
- Microsoft Research for SealPIR
- Sheaf theory (algebraic topology)
- Wreath product theory (group representation)
- Discrete Fourier Transform (character theory)

**Core Insight**: When routing has the right algebraic structure (position-dependent + global consistency), we can replace neural network optimization with a single linear solve - and it works on **encrypted data** too!

---

**Status**: Phase 2 infrastructure complete, OpenFHE integration next ✅

**Last Updated**: 2025-11-11

**Build Status**: ✅ All libraries compile, 41 tests passing (32 functional + 9 FHE stubs)
