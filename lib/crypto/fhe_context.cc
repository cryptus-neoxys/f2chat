// lib/crypto/fhe_context.cc
//
// Implementation of FHE crypto context management.

#include "lib/crypto/fhe_context.h"
#include "absl/strings/str_format.h"

namespace f2chat {

// Static factory method
absl::StatusOr<FHEContext> FHEContext::Create() {
  try {
    // Create BGV parameters for depth-0 operations
    lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS> parameters;
    
    // Set multiplicative depth to 0 (depth-0 operations only!)
    // This means no ciphertext-ciphertext multiplications are supported,
    // but we can still do: Add, Sub, Scalar multiplication, Rotation
    parameters.SetMultiplicativeDepth(0);
    
    // Set plaintext modulus to match our ring parameters
    parameters.SetPlaintextModulus(RingParams::kModulus);
    
    // Set ring dimension - OpenFHE may adjust this based on security
    // We request kDegree slots
    parameters.SetBatchSize(RingParams::kDegree);
    
    // Set security level to 128-bit
    parameters.SetSecurityLevel(lbcrypto::HEStd_128_classic);
    
    // Generate the crypto context
    CryptoContext cc = lbcrypto::GenCryptoContext(parameters);
    
    // Enable required features
    cc->Enable(lbcrypto::PKE);        // Public-key encryption
    cc->Enable(lbcrypto::KEYSWITCH);  // Key switching (for rotation)
    cc->Enable(lbcrypto::LEVELEDSHE); // Leveled SHE (for homomorphic ops)
    
    return FHEContext(cc);
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrFormat("Failed to create FHE context: %s", e.what()));
  }
}

absl::StatusOr<FHEKeyPair> FHEContext::GenerateKeyPair() const {
  if (!crypto_context_) {
    return absl::FailedPreconditionError("Crypto context not initialized");
  }
  
  try {
    // Generate key pair
    KeyPair kp = crypto_context_->KeyGen();
    
    // Generate evaluation keys for multiplication (even though we're depth-0,
    // we need this for scalar multiplication in some cases)
    crypto_context_->EvalMultKeyGen(kp.secretKey);
    
    // Generate rotation keys for all positions we might need
    // For homomorphic DFT, we need rotations by all positions
    std::vector<int32_t> rotations;
    for (int i = 1; i < RingParams::kDegree; ++i) {
      rotations.push_back(i);
      rotations.push_back(-i);
    }
    crypto_context_->EvalRotateKeyGen(kp.secretKey, rotations);
    
    return FHEKeyPair{kp.publicKey, kp.secretKey};
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrFormat("Failed to generate key pair: %s", e.what()));
  }
}

absl::StatusOr<Ciphertext> FHEContext::Encrypt(
    const std::vector<int64_t>& coefficients,
    const PublicKey& public_key) const {
  if (!crypto_context_) {
    return absl::FailedPreconditionError("Crypto context not initialized");
  }
  
  if (coefficients.size() > static_cast<size_t>(RingParams::kDegree)) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Too many coefficients: %d (max: %d)",
        coefficients.size(), RingParams::kDegree));
  }

  try {
    // Create a packed plaintext from coefficients
    Plaintext pt = crypto_context_->MakePackedPlaintext(coefficients);
    
    // Encrypt using the public key
    Ciphertext ct = crypto_context_->Encrypt(public_key, pt);
    
    return ct;
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrFormat("Encryption failed: %s", e.what()));
  }
}

absl::StatusOr<std::vector<int64_t>> FHEContext::Decrypt(
    const Ciphertext& ciphertext,
    const PrivateKey& private_key) const {
  if (!crypto_context_) {
    return absl::FailedPreconditionError("Crypto context not initialized");
  }
  
  try {
    Plaintext pt;
    crypto_context_->Decrypt(private_key, ciphertext, &pt);
    
    // Get the packed values - these are the polynomial coefficients
    std::vector<int64_t> result = pt->GetPackedValue();
    
    // Resize to match our expected degree
    if (result.size() > static_cast<size_t>(RingParams::kDegree)) {
      result.resize(RingParams::kDegree);
    }
    
    return result;
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrFormat("Decryption failed: %s", e.what()));
  }
}

// Homomorphic operations

absl::StatusOr<Ciphertext> FHEContext::HomomorphicAdd(
    const Ciphertext& ct1,
    const Ciphertext& ct2) const {
  if (!crypto_context_) {
    return absl::FailedPreconditionError("Crypto context not initialized");
  }
  
  try {
    // Homomorphic addition - depth-0 operation!
    Ciphertext result = crypto_context_->EvalAdd(ct1, ct2);
    return result;
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrFormat("Homomorphic addition failed: %s", e.what()));
  }
}

absl::StatusOr<Ciphertext> FHEContext::HomomorphicSubtract(
    const Ciphertext& ct1,
    const Ciphertext& ct2) const {
  if (!crypto_context_) {
    return absl::FailedPreconditionError("Crypto context not initialized");
  }
  
  try {
    // Homomorphic subtraction - depth-0 operation!
    Ciphertext result = crypto_context_->EvalSub(ct1, ct2);
    return result;
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrFormat("Homomorphic subtraction failed: %s", e.what()));
  }
}

// Since this is depth-0 BGV (no multiplicative depth available)
// True homomorphic multiplication (EvalMult) isn't possible without consuming depth
// For depth-0 BGV, we use repeated addition for scalar multiplication
// This is less efficient than EvalMult but works with depth-0
absl::StatusOr<Ciphertext> FHEContext::HomomorphicMultiplyScalar(
    const Ciphertext& ciphertext,
    int64_t scalar) const {
  if (!crypto_context_) {
    return absl::FailedPreconditionError("Crypto context not initialized");
  }
  
  try {
    
    if (scalar == 0) {
      // Return encryption of zeros
      std::vector<int64_t> zeros(RingParams::kDegree, 0);
      auto zero_pt = crypto_context_->MakePackedPlaintext(zeros);
      return crypto_context_->EvalAdd(ciphertext, 
             crypto_context_->EvalNegate(ciphertext));
    }
    
    if (scalar == 1) {
      return ciphertext;
    }
    
    // Handle negative scalars
    bool negate = scalar < 0;
    int64_t abs_scalar = negate ? -scalar : scalar;
    
    // Use binary method for efficiency: O(log n) additions instead of O(n)
    Ciphertext result = ciphertext;
    Ciphertext accumulator = ciphertext;
    abs_scalar--;  // We already have one copy in result
    
    while (abs_scalar > 0) {
      if (abs_scalar & 1) {
        result = crypto_context_->EvalAdd(result, accumulator);
      }
      abs_scalar >>= 1;
      if (abs_scalar > 0) {
        accumulator = crypto_context_->EvalAdd(accumulator, accumulator);
      }
    }
    
    if (negate) {
      result = crypto_context_->EvalNegate(result);
    }
    
    return result;
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrFormat("Homomorphic scalar multiplication failed: %s", e.what()));
  }
}

absl::StatusOr<Ciphertext> FHEContext::HomomorphicRotate(
    const Ciphertext& ciphertext,
    int positions) const {
  if (!crypto_context_) {
    return absl::FailedPreconditionError("Crypto context not initialized");
  }
  
  try {
    // Homomorphic rotation - depth-0 operation!
    // Uses automorphisms, not multiplications
    Ciphertext result = crypto_context_->EvalRotate(ciphertext, positions);
    return result;
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrFormat("Homomorphic rotation failed: %s", e.what()));
  }
}

// Accessors

int FHEContext::ring_dimension() const {
  return RingParams::kDegree;
}

int64_t FHEContext::modulus() const {
  return RingParams::kModulus;
}

// Private constructor
FHEContext::FHEContext(CryptoContext crypto_context)
    : crypto_context_(crypto_context) {}

}  // namespace f2chat
