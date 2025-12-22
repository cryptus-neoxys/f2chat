// lib/crypto/encrypted_polynomial.cc
//
// Implementation of encrypted polynomial wrapper.

#include "lib/crypto/encrypted_polynomial.h"
#include "absl/strings/str_format.h"

namespace f2chat {

namespace {
/**
 * @brief Computes the modular exponentiation of a base raised to an exponent.
 *
 * Computes (base^exp) mod modulus.
 *
 * @param base The base value. If negative, behavior depends on the platform's `%` for negatives; prefer passing a non-negative base.
 * @param exp Non-negative exponent (must be >= 0).
 * @param modulus Modulus value (must be > 0).
 * @return int64_t The value (base^exp) mod modulus in the range [0, modulus-1] when `modulus > 0`.
 */
int64_t ModPow(int64_t base, int64_t exp, int64_t modulus) {
  int64_t result = 1;
  base %= modulus;
  while (exp > 0) {
    if (exp & 1) {
      result = (result * base) % modulus;
    }
    base = (base * base) % modulus;
    exp >>= 1;
  }
  return result;
}

/**
 * @brief Computes the modular multiplicative inverse of `a` modulo `modulus`.
 *
 * Uses the extended Euclidean algorithm to produce an integer `x` such that
 * (a * x) mod modulus == 1 when `a` and `modulus` are coprime.
 *
 * @param a Value whose modular inverse is sought.
 * @param modulus Modulus for the inverse computation.
 * @return int64_t Modular inverse in the range [0, modulus - 1]; returns 0 when `modulus == 1`.
 *
 * @note The result is only a valid multiplicative inverse when `gcd(a, modulus) == 1`.
 */
int64_t ModInverse(int64_t a, int64_t modulus) {
  int64_t m0 = modulus, t, q;
  int64_t x0 = 0, x1 = 1;
  
  if (modulus == 1) return 0;
  
  while (a > 1) {
    q = a / modulus;
    t = modulus;
    modulus = a % modulus;
    a = t;
    t = x0;
    x0 = x1 - q * x0;
    x1 = t;
  }
  
  if (x1 < 0) x1 += m0;
  return x1;
}

// Helper: Find a primitive nth root of unity modulo p
/**
 * @brief Finds a primitive n-th root of unity modulo the given modulus.
 *
 * Computes a value ω such that ω^n ≡ 1 (mod modulus). This function assumes
 * that n divides (modulus - 1) and that modulus is the prime 65537; it uses
 * 3 as a multiplicative generator for Z_modulus^* and returns 3^((modulus-1)/n) mod modulus.
 *
 * @param n The order of the root of unity to find; must divide (modulus - 1).
 * @param modulus The modulus to operate in (expected 65537).
 * @return int64_t A primitive n-th root of unity modulo modulus.
 */
int64_t FindRootOfUnity(int n, int64_t modulus) {
  // For modulus = 65537 = 2^16 + 1, we know p-1 = 2^16
  // So any power of 2 divides (p-1)
  
  // A generator for Z_p^* is typically a small number
  // For p = 65537, g = 3 is a generator
  int64_t g = 3;
  
  // ω = g^((p-1)/n) is a primitive nth root of unity
  int64_t exponent = (modulus - 1) / n;
  return ModPow(g, exponent, modulus);
}

}  // namespace

/**
 * @brief Encrypts a plaintext polynomial using the provided public key and FHE context.
 *
 * @param polynomial Plaintext polynomial to encrypt.
 * @param public_key Public key used for encryption.
 * @param fhe_context Context providing FHE operations and parameters.
 * @return absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial constructed from the resulting ciphertext on success; an error status on failure.
 */
absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::Encrypt(
    const Polynomial& polynomial,
    const PublicKey& public_key,
    const FHEContext& fhe_context) {
  // Encrypt polynomial coefficients using FHE context
  auto ciphertext_or = fhe_context.Encrypt(polynomial.coefficients(), public_key);
  if (!ciphertext_or.ok()) {
    return ciphertext_or.status();
  }

  return EncryptedPolynomial(std::move(ciphertext_or).value());
}

// Decrypt to plaintext polynomial
absl::StatusOr<Polynomial> EncryptedPolynomial::Decrypt(
    const PrivateKey& private_key,
    const FHEContext& fhe_context) const {
  // Decrypt ciphertext using FHE context
  auto coefficients_or = fhe_context.Decrypt(ciphertext_, private_key);
  if (!coefficients_or.ok()) {
    return coefficients_or.status();
  }

  // Construct polynomial from decrypted coefficients
  return Polynomial(std::move(coefficients_or).value());
}

// Homomorphic operations

absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::Add(
    const EncryptedPolynomial& other,
    const FHEContext& fhe_context) const {
  // Homomorphic addition: Enc(a) + Enc(b) → Enc(a + b)
  auto result_ct_or = fhe_context.HomomorphicAdd(ciphertext_, other.ciphertext_);
  if (!result_ct_or.ok()) {
    return result_ct_or.status();
  }

  return EncryptedPolynomial(std::move(result_ct_or).value());
}

absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::Subtract(
    const EncryptedPolynomial& other,
    const FHEContext& fhe_context) const {
  // Homomorphic subtraction: Enc(a) - Enc(b) → Enc(a - b)
  auto result_ct_or = fhe_context.HomomorphicSubtract(ciphertext_, other.ciphertext_);
  if (!result_ct_or.ok()) {
    return result_ct_or.status();
  }

  return EncryptedPolynomial(std::move(result_ct_or).value());
}

absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::MultiplyScalar(
    int64_t scalar,
    const FHEContext& fhe_context) const {
  // Homomorphic scalar multiplication: k * Enc(a) → Enc(k * a)
  auto result_ct_or = fhe_context.HomomorphicMultiplyScalar(ciphertext_, scalar);
  if (!result_ct_or.ok()) {
    return result_ct_or.status();
  }

  return EncryptedPolynomial(std::move(result_ct_or).value());
}

absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::Rotate(
    int positions,
    const FHEContext& fhe_context) const {
  // Homomorphic rotation: Enc(a) → Enc(rotated(a))
  auto result_ct_or = fhe_context.HomomorphicRotate(ciphertext_, positions);
  if (!result_ct_or.ok()) {
    return result_ct_or.status();
  }

  return EncryptedPolynomial(std::move(result_ct_or).value());
}

absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::Negate(
    const FHEContext& fhe_context) const {
  // Homomorphic negation: Enc(a) → Enc(-a)
  // Implemented as scalar multiplication by -1
  return MultiplyScalar(-1, fhe_context);
}

/**
 * @brief Projects an encrypted polynomial onto a single character index using a homomorphic DFT.
 *
 * Computes the projection χ_j applied to the encrypted polynomial:
 * Proj_χ_j(p) = (1/n) * Σ_{k=0}^{n-1} χ_j(k) * Rotate(p, k),
 * where χ_j(k) = ω^{j*k} in the ring modulus and ω is a primitive n-th root of unity.
 *
 * @param character_index Index of the character to project onto (0 .. RingParams::kNumCharacters-1).
 * @param fhe_context Context providing homomorphic operations required for rotations, additions, and scalar multiplications.
 * @return absl::StatusOr<EncryptedPolynomial> The encrypted polynomial projected to the requested character on success; an error Status on failure.
 */
absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::ProjectToCharacter(
    int character_index,
    const FHEContext& fhe_context) const {
  if (character_index < 0 || character_index >= RingParams::kNumCharacters) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Invalid character index: %d (must be 0 to %d)",
        character_index, RingParams::kNumCharacters - 1));
  }

  try {
    const int n = RingParams::kNumCharacters;
    const int64_t modulus = RingParams::kModulus;
    
    // Find primitive nth root of unity modulo p
    int64_t omega = FindRootOfUnity(n, modulus);
    
    // Compute character projection using DFT formula:
    // Proj_χⱼ(p) = (1/n) * Σₖ χⱼ(k) * p(ωᵏ)
    // where χⱼ(k) = ω^(j*k) mod p
    
    // Start with the k=0 term (no rotation needed)
    // χⱼ(0) = ω^0 = 1, so we just scale by 1
    auto result = *this;
    
    // For each position k > 0, compute ω^(j*k) and add scaled rotated ciphertext
    for (int k = 1; k < n; ++k) {
      // Compute character value: χⱼ(k) = ω^(j*k) mod p
      int64_t chi_jk = ModPow(omega, static_cast<int64_t>(character_index) * k, modulus);
      
      // Rotate ciphertext by k positions
      auto rotated_or = Rotate(k, fhe_context);
      if (!rotated_or.ok()) return rotated_or.status();
      
      // Scale by character value
      auto scaled_or = rotated_or.value().MultiplyScalar(chi_jk, fhe_context);
      if (!scaled_or.ok()) return scaled_or.status();
      
      // Add to accumulator
      auto sum_or = result.Add(scaled_or.value(), fhe_context);
      if (!sum_or.ok()) return sum_or.status();
      
      result = sum_or.value();
    }
    
    // Scale by 1/n (modular inverse of n)
    int64_t n_inv = ModInverse(n, modulus);
    return result.MultiplyScalar(n_inv, fhe_context);
    
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrFormat("Character projection failed: %s", e.what()));
  }
}

/**
 * @brief Compute homomorphic projections of this encrypted polynomial onto every character in the ring.
 *
 * @param fhe_context FHE evaluation context used to perform the required homomorphic operations (rotations, scalar multiplies, additions).
 * @return std::vector<EncryptedPolynomial> Vector of projections where element `j` is the projection onto character index `j` (indices 0..RingParams::kNumCharacters-1); on failure returns the corresponding error status.
 */
absl::StatusOr<std::vector<EncryptedPolynomial>>
EncryptedPolynomial::ProjectToAllCharacters(
    const FHEContext& fhe_context) const {
  std::vector<EncryptedPolynomial> projections;
  projections.reserve(RingParams::kNumCharacters);

  // Project onto each character χⱼ
  for (int j = 0; j < RingParams::kNumCharacters; ++j) {
    auto proj_or = ProjectToCharacter(j, fhe_context);
    if (!proj_or.ok()) {
      return proj_or.status();
    }
    projections.push_back(std::move(proj_or).value());
  }

  return projections;
}

// Debug string (does NOT decrypt!)
std::string EncryptedPolynomial::DebugString() const {
  return absl::StrFormat(
      "EncryptedPolynomial{ciphertext_ptr=%p}",
      ciphertext_.get());
}

// Private constructor
EncryptedPolynomial::EncryptedPolynomial(Ciphertext ciphertext)
    : ciphertext_(ciphertext) {}

}  // namespace f2chat