// lib/crypto/fhe_context.h
//
// FHE crypto context management for blind polynomial routing.
//
// Wraps OpenFHE's BGV scheme to provide:
// - Crypto context initialization (ring parameters, security level)
// - Key pair generation (public/private keys)
// - Encryption/decryption of polynomial coefficients
// - Depth-0 operations (addition, subtraction, rotation)
//
// Key Properties:
// - BGV scheme for integer arithmetic (matches polynomial coefficients)
// - Ring dimension matched to PolynomialParams
// - Depth-0 operations only (no bootstrapping needed!)
//
// Author: bon-cdp (shakilflynn@gmail.com)
// Date: 2025-11-11

#ifndef F2CHAT_LIB_CRYPTO_FHE_CONTEXT_H_
#define F2CHAT_LIB_CRYPTO_FHE_CONTEXT_H_

#include <memory>
#include <vector>
#include "lib/crypto/polynomial_params.h"
#include "absl/status/statusor.h"
#include "absl/status/status.h"

// OpenFHE headers for BGV scheme
#include "openfhe.h"

/**
 * Create a default FHE context configured for the BGV scheme and depth-0 operations.
 *
 * @returns FHEContext initialized with ring/modulus/security parameters suitable for this library,
 *          or an error status if OpenFHE initialization fails.
 */
/**
 * Generate a new FHE key pair and the necessary evaluation keys for depth-0 homomorphic ops.
 *
 * @returns FHEKeyPair containing the public key for encryption and the private key for decryption,
 *          or an error status if key generation fails.
 */
/**
 * Encrypt a polynomial represented by its coefficient vector with the given public key.
 *
 * @param coefficients Polynomial coefficients to encrypt; size must not exceed the ring dimension.
 * @param public_key Recipient's public key used for encryption.
 * @returns Ciphertext encrypting the provided polynomial, or an error status if encryption fails.
 */
/**
 * Decrypt a ciphertext to recover the polynomial coefficients using the provided private key.
 *
 * @param ciphertext Encrypted polynomial to decrypt.
 * @param private_key Private key used to decrypt the ciphertext.
 * @returns Decrypted polynomial coefficients, or an error status if decryption fails.
 */
/**
 * Compute the homomorphic sum of two ciphertexts.
 *
 * @param ct1 First encrypted polynomial operand.
 * @param ct2 Second encrypted polynomial operand.
 * @returns Ciphertext representing the encrypted element-wise sum, or an error status if the operation fails.
 */
/**
 * Compute the homomorphic difference of two ciphertexts (ct1 - ct2).
 *
 * @param ct1 Minuend encrypted polynomial.
 * @param ct2 Subtrahend encrypted polynomial.
 * @returns Ciphertext representing the encrypted element-wise difference, or an error status if the operation fails.
 */
/**
 * Multiply an encrypted polynomial by a plaintext scalar homomorphically.
 *
 * @param ciphertext Encrypted polynomial to scale.
 * @param scalar Plaintext integer scalar multiplier.
 * @returns Ciphertext representing the encrypted scaled polynomial, or an error status if the operation fails.
 */
/**
 * Rotate the coefficients of an encrypted polynomial cyclically by a number of positions.
 *
 * @param ciphertext Encrypted polynomial to rotate.
 * @param positions Number of positions to rotate (positive for left, negative for right).
 * @returns Ciphertext representing the rotated encrypted polynomial, or an error status if the operation fails
 *          or rotation evaluation keys have not been generated.
 */
/**
 * Access the underlying OpenFHE crypto context.
 *
 * @returns The OpenFHE CryptoContext used by this FHEContext.
 */
/**
 * Obtain the ring dimension used by the crypto context.
 *
 * @returns The ring dimension (number of coefficients) for polynomials in this context.
 */
/**
 * Obtain the plaintext modulus used by the crypto context.
 *
 * @returns The modulus used for plaintext arithmetic in this context.
 */
namespace f2chat {

// Real OpenFHE types for BGV scheme
using CryptoContext = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;
using Ciphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using Plaintext = lbcrypto::Plaintext;
using PublicKey = lbcrypto::PublicKey<lbcrypto::DCRTPoly>;
using PrivateKey = lbcrypto::PrivateKey<lbcrypto::DCRTPoly>;
using KeyPair = lbcrypto::KeyPair<lbcrypto::DCRTPoly>;

// FHE key pair for a user (public key shared, private key device-held).
struct FHEKeyPair {
  PublicKey public_key;    // Shared with contacts (for encryption)
  PrivateKey private_key;  // Device-held only (for decryption)
};

// FHE crypto context manager.
//
// This class manages the OpenFHE crypto context and provides
// high-level operations for encrypting/decrypting polynomials.
//
// Thread Safety: Thread-safe after initialization (immutable context).
//
// Performance:
// - Encryption: O(n log n) where n = ring dimension
// - Decryption: O(n log n)
// - Homomorphic Add/Sub: O(n) (depth-0!)
// - Homomorphic Rotate: O(n log n) (depth-0!)
class FHEContext {
 public:
  // Creates FHE context with default parameters.
  //
  // Initializes OpenFHE BGV scheme with:
  // - Ring dimension: matched to RingParams::kDegree
  // - Modulus: matched to RingParams::kModulus
  // - Security level: 128-bit (HEStd_128_classic)
  // - Multiplicative depth: 0 (depth-0 operations only!)
  //
  // Returns:
  //   FHEContext instance ready for key generation and encryption
  //   Error if OpenFHE initialization fails
  //
  // Performance: ~10ms (one-time setup)
  static absl::StatusOr<FHEContext> Create();

  // Generates a new FHE key pair.
  //
  // Creates:
  // - Public key: For encryption by contacts
  // - Private key: For decryption (device-held only)
  // - Evaluation keys: For homomorphic operations (rotation, etc.)
  //
  // Returns:
  //   FHEKeyPair with public/private keys
  //   Error if key generation fails
  //
  // Performance: ~50ms (generates keys for depth-0 operations)
  absl::StatusOr<FHEKeyPair> GenerateKeyPair() const;

  // Encrypts polynomial coefficients.
  //
  // Encrypts a vector of integers (polynomial coefficients) using
  // the recipient's public key. Result is a ciphertext that can be
  // operated on homomorphically.
  //
  // Args:
  //   coefficients: Polynomial coefficients to encrypt
  //   public_key: Recipient's public key
  //
  // Returns:
  //   Ciphertext (encrypted polynomial)
  //   Error if encryption fails or coefficients.size() > ring dimension
  //
  // Performance: O(n log n) where n = ring dimension
  absl::StatusOr<Ciphertext> Encrypt(
      const std::vector<int64_t>& coefficients,
      const PublicKey& public_key) const;

  // Decrypts polynomial coefficients.
  //
  // Decrypts a ciphertext using the private key, recovering the
  // original polynomial coefficients.
  //
  // Args:
  //   ciphertext: Encrypted polynomial
  //   private_key: Decryption key (device-held)
  //
  // Returns:
  //   Decrypted polynomial coefficients
  //   Error if decryption fails
  //
  // Performance: O(n log n)
  absl::StatusOr<std::vector<int64_t>> Decrypt(
      const Ciphertext& ciphertext,
      const PrivateKey& private_key) const;

  // Homomorphic operations (depth-0).

  // Homomorphic addition: Enc(a) + Enc(b) → Enc(a + b).
  //
  // Args:
  //   ct1: Encrypted polynomial a
  //   ct2: Encrypted polynomial b
  //
  // Returns:
  //   Encrypted sum Enc(a + b)
  //   Error if operation fails
  //
  // Performance: O(n), depth-0
  absl::StatusOr<Ciphertext> HomomorphicAdd(
      const Ciphertext& ct1,
      const Ciphertext& ct2) const;

  // Homomorphic subtraction: Enc(a) - Enc(b) → Enc(a - b).
  //
  // Args:
  //   ct1: Encrypted polynomial a
  //   ct2: Encrypted polynomial b
  //
  // Returns:
  //   Encrypted difference Enc(a - b)
  //   Error if operation fails
  //
  // Performance: O(n), depth-0
  absl::StatusOr<Ciphertext> HomomorphicSubtract(
      const Ciphertext& ct1,
      const Ciphertext& ct2) const;

  // Homomorphic scalar multiplication: k * Enc(a) → Enc(k * a).
  //
  // Multiplies encrypted polynomial by a plaintext scalar.
  //
  // Args:
  //   ciphertext: Encrypted polynomial a
  //   scalar: Plaintext scalar k
  //
  // Returns:
  //   Encrypted product Enc(k * a)
  //   Error if operation fails
  //
  // Performance: O(n), depth-0
  absl::StatusOr<Ciphertext> HomomorphicMultiplyScalar(
      const Ciphertext& ciphertext,
      int64_t scalar) const;

  // Homomorphic rotation: Enc(a) → Enc(rotated(a)).
  //
  // Rotates encrypted polynomial coefficients cyclically.
  // Requires rotation keys to be generated.
  //
  // Args:
  //   ciphertext: Encrypted polynomial
  //   positions: Number of positions to rotate
  //
  // Returns:
  //   Encrypted rotated polynomial
  //   Error if operation fails or rotation keys not generated
  //
  // Performance: O(n log n), depth-0
  absl::StatusOr<Ciphertext> HomomorphicRotate(
      const Ciphertext& ciphertext,
      int positions) const;

  // Accessors.

  CryptoContext crypto_context() const { return crypto_context_; }

  // Ring parameters.
  int ring_dimension() const;
  int64_t modulus() const;

 private:
  explicit FHEContext(CryptoContext crypto_context);

  // OpenFHE crypto context (manages all FHE operations)
  CryptoContext crypto_context_;
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_CRYPTO_FHE_CONTEXT_H_