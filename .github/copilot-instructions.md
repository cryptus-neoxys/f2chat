# f2chat AI Coding Instructions

## Project Overview

f2chat is a metadata-private messaging system using **Fully Homomorphic Encryption (FHE)**.
The core innovation is **Blind Routing**: the server routes encrypted messages using **Sheaf-Wreath Attention** without ever decrypting them.

## Architecture

- **Client**: Holds private keys. Encrypts polynomials (IDs, messages) and decrypts results.
- **Server**: Performs **blind algebraic routing** on encrypted data.
  - **Input**: Encrypted polynomials (`Enc(P_alice)`, `Enc(P_bob)`, `Enc(message)`).
  - **Operation**: Homomorphic addition, subtraction, scalar multiplication, and rotation.
  - **Output**: Encrypted routed message stored at an encrypted mailbox location.
- **Constraint**: All server-side operations must be **Depth-0** (no bootstrapping).

## Key Components

- **`lib/crypto/fhe_context.h`**: Manages OpenFHE BGV context.
  - Use `FHEContext::Create()` to initialize.
  - Supports `HomomorphicAdd`, `HomomorphicSubtract`, `HomomorphicRotate`, `HomomorphicMultiplyScalar`.
- **`lib/crypto/encrypted_polynomial.h`**: Wrapper for FHE ciphertexts.
  - **Server-Safe**: `Add`, `Subtract`, `Rotate`, `MultiplyScalar`, `ProjectToCharacter`.
  - **Client-Only**: `Encrypt`, `Decrypt`.
- **`lib/crypto/polynomial.h`**: Plaintext polynomial arithmetic (Ring $Z_p[x]/(x^n+1)$).

## Development Workflow

- **Build System**: Bazel
  - Build all: `bazel build //lib/...`
  - Run tests: `bazel test //test/...`
  - Run specific test: `bazel test //test/crypto:encrypted_polynomial_test --test_output=all`
- **Dependencies**: OpenFHE (via `third_party/openfhe.BUILD`), Abseil, Eigen, GoogleTest.

## Local Setup & Running

- **Prerequisites**:
  - Bazel (latest version)
  - C++ Compiler (Clang/GCC with C++17 support)
  - Git
- **Setup**:
  1. Clone the repository.
  2. Run `bazel build //lib/...` to fetch dependencies (including OpenFHE) and build the core library.
- **Running Tests**:
  - Run all tests: `bazel test //test/...`
  - Run Alice→Bob integration test: `bazel test //test/integration:alice_to_bob_test --test_output=all`
  - Run FHE stub tests: `bazel test //test/crypto:encrypted_polynomial_test --test_output=all`

## Coding Conventions

- **Language**: C++ (modern standards).
- **Style**: Google C++ Style (use `absl::StatusOr` for error handling).
- **FHE Patterns**:
  - **NEVER** decrypt on the server.
  - **ALWAYS** check for Depth-0 compatibility (avoid complex multiplications).
  - Use `EncryptedPolynomial` for all high-level FHE logic.
  - Use `FHEContext` for low-level OpenFHE interactions.

## Current Status (Phase 2)

- **Focus**: Implementing FHE infrastructure.
- **Active Tasks**:
  - Implement OpenFHE integration in `lib/crypto/fhe_context.cc`.
  - Implement `ProjectToCharacter` in `lib/crypto/encrypted_polynomial.cc`.
  - Create `lib/network/encrypted_mailbox.{h,cc}`.
