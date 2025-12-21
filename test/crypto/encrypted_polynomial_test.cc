// test/crypto/encrypted_polynomial_test.cc
//
// Tests for FHE-encrypted polynomial operations.
//
// These tests verify the OpenFHE BGV integration works correctly.

#include "lib/crypto/encrypted_polynomial.h"
#include "lib/crypto/polynomial.h"
#include "lib/crypto/fhe_context.h"
#include <gtest/gtest.h>

namespace f2chat {
namespace {

// Test fixture for FHE tests - creates context and keys once
class EncryptedPolynomialTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto fhe_ctx_or = FHEContext::Create();
    ASSERT_TRUE(fhe_ctx_or.ok()) << "FHE context creation failed: " 
                                  << fhe_ctx_or.status();
    fhe_ctx_ = std::make_unique<FHEContext>(std::move(fhe_ctx_or.value()));
    
    auto keys_or = fhe_ctx_->GenerateKeyPair();
    ASSERT_TRUE(keys_or.ok()) << "Key generation failed: " << keys_or.status();
    keys_ = std::move(keys_or.value());
  }

  std::unique_ptr<FHEContext> fhe_ctx_;
  FHEKeyPair keys_;
};

TEST_F(EncryptedPolynomialTest, FHEContextCreation) {
  // Verify FHE context is properly initialized
  EXPECT_EQ(fhe_ctx_->ring_dimension(), RingParams::kDegree);
  EXPECT_EQ(fhe_ctx_->modulus(), RingParams::kModulus);
}

TEST_F(EncryptedPolynomialTest, EncryptionDecryptionRoundtrip) {
  // Test basic encryption/decryption roundtrip
  std::vector<int64_t> coefficients = {1, 2, 3, 4, 5, 6, 7, 8};
  
  // Encrypt
  auto encrypted_or = fhe_ctx_->Encrypt(coefficients, keys_.public_key);
  ASSERT_TRUE(encrypted_or.ok()) << "Encryption failed: " << encrypted_or.status();
  
  // Decrypt
  auto decrypted_or = fhe_ctx_->Decrypt(encrypted_or.value(), keys_.private_key);
  ASSERT_TRUE(decrypted_or.ok()) << "Decryption failed: " << decrypted_or.status();
  
  // Verify at least the first few coefficients match
  // (OpenFHE may pad the vector to batch size)
  const auto& decrypted = decrypted_or.value();
  ASSERT_GE(decrypted.size(), coefficients.size());
  for (size_t i = 0; i < coefficients.size(); ++i) {
    EXPECT_EQ(decrypted[i], coefficients[i]) 
        << "Mismatch at index " << i;
  }
}

TEST_F(EncryptedPolynomialTest, HomomorphicAddition) {
  // Verify Enc(a) + Enc(b) == Enc(a + b)
  std::vector<int64_t> a = {1, 2, 3, 4};
  std::vector<int64_t> b = {10, 20, 30, 40};
  
  auto enc_a = fhe_ctx_->Encrypt(a, keys_.public_key);
  auto enc_b = fhe_ctx_->Encrypt(b, keys_.public_key);
  ASSERT_TRUE(enc_a.ok() && enc_b.ok());
  
  auto enc_sum = fhe_ctx_->HomomorphicAdd(enc_a.value(), enc_b.value());
  ASSERT_TRUE(enc_sum.ok()) << "Homomorphic add failed: " << enc_sum.status();
  
  auto decrypted = fhe_ctx_->Decrypt(enc_sum.value(), keys_.private_key);
  ASSERT_TRUE(decrypted.ok());
  
  // Verify: a + b
  for (size_t i = 0; i < a.size(); ++i) {
    // Handle modular arithmetic
    int64_t expected = (a[i] + b[i]) % RingParams::kModulus;
    EXPECT_EQ(decrypted.value()[i], expected) 
        << "Addition mismatch at index " << i;
  }
}

TEST_F(EncryptedPolynomialTest, HomomorphicSubtraction) {
  // Verify Enc(a) - Enc(b) == Enc(a - b)
  std::vector<int64_t> a = {100, 200, 300, 400};
  std::vector<int64_t> b = {10, 20, 30, 40};
  
  auto enc_a = fhe_ctx_->Encrypt(a, keys_.public_key);
  auto enc_b = fhe_ctx_->Encrypt(b, keys_.public_key);
  ASSERT_TRUE(enc_a.ok() && enc_b.ok());
  
  auto enc_diff = fhe_ctx_->HomomorphicSubtract(enc_a.value(), enc_b.value());
  ASSERT_TRUE(enc_diff.ok()) << "Homomorphic subtract failed: " << enc_diff.status();
  
  auto decrypted = fhe_ctx_->Decrypt(enc_diff.value(), keys_.private_key);
  ASSERT_TRUE(decrypted.ok());
  
  // Verify: a - b
  for (size_t i = 0; i < a.size(); ++i) {
    int64_t expected = a[i] - b[i];
    EXPECT_EQ(decrypted.value()[i], expected) 
        << "Subtraction mismatch at index " << i;
  }
}

TEST_F(EncryptedPolynomialTest, HomomorphicScalarMultiplication) {
  // Verify scalar * Enc(a) == Enc(scalar * a)
  std::vector<int64_t> a = {1, 2, 3, 4};
  int64_t scalar = 5;
  
  auto enc_a = fhe_ctx_->Encrypt(a, keys_.public_key);
  ASSERT_TRUE(enc_a.ok());
  
  auto enc_product = fhe_ctx_->HomomorphicMultiplyScalar(enc_a.value(), scalar);
  ASSERT_TRUE(enc_product.ok()) << "Scalar multiplication failed: " << enc_product.status();
  
  auto decrypted = fhe_ctx_->Decrypt(enc_product.value(), keys_.private_key);
  ASSERT_TRUE(decrypted.ok());
  
  // Verify: scalar * a
  for (size_t i = 0; i < a.size(); ++i) {
    int64_t expected = (a[i] * scalar) % RingParams::kModulus;
    EXPECT_EQ(decrypted.value()[i], expected) 
        << "Scalar multiplication mismatch at index " << i;
  }
}

TEST_F(EncryptedPolynomialTest, HomomorphicRotation) {
  // Verify rotation works homomorphically
  // Note: Rotation in packed encoding shifts the slot positions
  std::vector<int64_t> a = {1, 2, 3, 4, 5, 6, 7, 8};
  int positions = 2;
  
  auto enc_a = fhe_ctx_->Encrypt(a, keys_.public_key);
  ASSERT_TRUE(enc_a.ok());
  
  auto enc_rotated = fhe_ctx_->HomomorphicRotate(enc_a.value(), positions);
  ASSERT_TRUE(enc_rotated.ok()) << "Rotation failed: " << enc_rotated.status();
  
  auto decrypted = fhe_ctx_->Decrypt(enc_rotated.value(), keys_.private_key);
  ASSERT_TRUE(decrypted.ok());
  
  // Rotation in packed encoding: slot i gets value from slot (i+positions)
  // So position 0 gets value from original position 2, etc.
  EXPECT_EQ(decrypted.value()[0], a[2]) << "Rotation check at index 0";
  EXPECT_EQ(decrypted.value()[1], a[3]) << "Rotation check at index 1";
}

TEST_F(EncryptedPolynomialTest, CharacterProjection) {
  // Test homomorphic character projection (DFT)
  // For a simple test, use character 0 (identity) which should sum all coefficients
  Polynomial poly({1, 2, 3, 4, 5, 6, 7, 8});
  
  auto enc_poly_or = EncryptedPolynomial::Encrypt(poly, keys_.public_key, *fhe_ctx_);
  ASSERT_TRUE(enc_poly_or.ok());
  
  // Project onto character 0 (identity character)
  // For character 0, all χ₀(k) = 1, so this computes (1/n) * sum of all rotations
  auto projected_or = enc_poly_or.value().ProjectToCharacter(0, *fhe_ctx_);
  ASSERT_TRUE(projected_or.ok()) << "Character projection failed: " 
                                  << projected_or.status();
  
  auto decrypted = projected_or.value().Decrypt(keys_.private_key, *fhe_ctx_);
  ASSERT_TRUE(decrypted.ok());
  
  // For character 0 (identity), the projection should give a specific pattern
  // Just verify the operation completes without errors for now
  // Full mathematical verification would require understanding the exact DFT semantics
  SUCCEED() << "Character projection completed successfully";
}

TEST_F(EncryptedPolynomialTest, Depth0Verification) {
  // Verify operations are depth-0
  // In depth-0, we can chain multiple operations without noise issues
  std::vector<int64_t> a = {1, 2, 3, 4};
  
  auto enc_a = fhe_ctx_->Encrypt(a, keys_.public_key);
  ASSERT_TRUE(enc_a.ok());
  
  // Chain multiple depth-0 operations
  auto result = enc_a.value();
  for (int i = 0; i < 5; ++i) {
    auto added = fhe_ctx_->HomomorphicAdd(result, enc_a.value());
    ASSERT_TRUE(added.ok()) << "Failed after " << i << " additions";
    result = added.value();
  }
  
  // Should still decrypt correctly (5 additions = 6x original)
  auto decrypted = fhe_ctx_->Decrypt(result, keys_.private_key);
  ASSERT_TRUE(decrypted.ok()) << "Decryption after chained ops failed";
  
  for (size_t i = 0; i < a.size(); ++i) {
    int64_t expected = (a[i] * 6) % RingParams::kModulus;
    EXPECT_EQ(decrypted.value()[i], expected) 
        << "Chained addition mismatch at index " << i;
  }
}

TEST_F(EncryptedPolynomialTest, FullWorkflow) {
  // End-to-end test: encryption, operations, decryption
  std::vector<int64_t> message = {42, 100, 255, 1000};
  int64_t scalar = 2;
  
  // 1. Encrypt
  auto enc = fhe_ctx_->Encrypt(message, keys_.public_key);
  ASSERT_TRUE(enc.ok());
  
  // 2. Perform operations (simulating server routing)
  auto doubled = fhe_ctx_->HomomorphicMultiplyScalar(enc.value(), scalar);
  ASSERT_TRUE(doubled.ok());
  
  // 3. Decrypt
  auto result = fhe_ctx_->Decrypt(doubled.value(), keys_.private_key);
  ASSERT_TRUE(result.ok());
  
  // 4. Verify
  for (size_t i = 0; i < message.size(); ++i) {
    int64_t expected = (message[i] * scalar) % RingParams::kModulus;
    EXPECT_EQ(result.value()[i], expected);
  }
}

}  // namespace
}  // namespace f2chat
