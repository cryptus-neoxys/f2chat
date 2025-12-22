// test/crypto/fhe_benchmark.cc
//
// Performance benchmarks for FHE operations

#include "lib/crypto/fhe_context.h"
#include "lib/crypto/encrypted_polynomial.h"
#include "lib/crypto/polynomial.h"
#include <benchmark/benchmark.h>

namespace f2chat {

// Shared context and keys for benchmarks
static std::unique_ptr<FHEContext> g_fhe_ctx;
static FHEKeyPair g_keys;
static bool g_initialized = false;

/**
 * @brief Ensure the shared FHE context and key pair are initialized for benchmarks.
 *
 * If the shared state is not yet initialized, this function creates an FHE context
 * and generates a key pair. On success it stores the context in `g_fhe_ctx`, the
 * keys in `g_keys`, and sets `g_initialized` to true. If context creation or key
 * generation fails, the benchmark `state` is marked skipped with an error message
 * and the function returns without modifying the global initialized flag.
 *
 * @param state Benchmark state used to skip the benchmark on initialization failure.
 */
static void EnsureInitialized(benchmark::State& state) {
  if (!g_initialized) {
    auto fhe_ctx_or = FHEContext::Create();
    if (!fhe_ctx_or.ok()) {
      state.SkipWithError("FHE context creation failed");
      return;
    }
    g_fhe_ctx = std::make_unique<FHEContext>(std::move(fhe_ctx_or.value()));
    
    auto keys_or = g_fhe_ctx->GenerateKeyPair();
    if (!keys_or.ok()) {
      state.SkipWithError("Key generation failed");
      return;
    }
    g_keys = std::move(keys_or.value());
    g_initialized = true;
  }
}

/**
 * @brief Benchmarks the cost of creating an FHEContext.
 *
 * Repeatedly calls FHEContext::Create() for each benchmark iteration to measure context creation performance.
 *
 * @param state Benchmark state provided by Google Benchmark that controls iteration timing and reporting.
 */
static void BM_FHEContextCreation(benchmark::State& state) {
  for (auto _ : state) {
    auto fhe_ctx = FHEContext::Create();
    benchmark::DoNotOptimize(fhe_ctx);
  }
}
BENCHMARK(BM_FHEContextCreation);

/**
 * @brief Benchmarks generating a fresh FHE key pair from the shared FHE context.
 *
 * Repeatedly invokes key-pair generation to measure its performance. Uses the
 * translation-unit shared FHE context and records timing via the provided
 * benchmark state.
 */
static void BM_KeyGeneration(benchmark::State& state) {
  EnsureInitialized(state);
  for (auto _ : state) {
    auto keys = g_fhe_ctx->GenerateKeyPair();
    benchmark::DoNotOptimize(keys);
  }
}
BENCHMARK(BM_KeyGeneration);

/**
 * @brief Measures the performance of encrypting a polynomial using the shared FHE context and public key.
 *
 * Repeatedly encrypts a fixed Polynomial ({1,2,3,4,5,6,7,8}) and prevents the compiler from optimizing away the result.
 * If the shared FHE context or key pair cannot be initialized, the benchmark is skipped.
 *
 * @param state The benchmark state driving iterations.
 */
static void BM_Encryption(benchmark::State& state) {
  EnsureInitialized(state);
  Polynomial poly({1, 2, 3, 4, 5, 6, 7, 8});
  
  for (auto _ : state) {
    auto enc = EncryptedPolynomial::Encrypt(poly, g_keys.public_key, *g_fhe_ctx);
    benchmark::DoNotOptimize(enc);
  }
}
BENCHMARK(BM_Encryption);

/**
 * @brief Measures the cost of decrypting an EncryptedPolynomial.
 *
 * Pre-encrypts a fixed polynomial using the shared FHE context and public key,
 * then repeatedly decrypts that ciphertext using the corresponding private key
 * to benchmark decryption performance.
 */
static void BM_Decryption(benchmark::State& state) {
  EnsureInitialized(state);
  Polynomial poly({1, 2, 3, 4, 5, 6, 7, 8});
  auto enc = EncryptedPolynomial::Encrypt(poly, g_keys.public_key, *g_fhe_ctx).value();
  
  for (auto _ : state) {
    auto dec = enc.Decrypt(g_keys.private_key, *g_fhe_ctx);
    benchmark::DoNotOptimize(dec);
  }
}
BENCHMARK(BM_Decryption);

/**
 * Benchmarks homomorphic addition of two encrypted polynomials using the shared FHE context.
 *
 * Encrypts two small polynomials with the shared public key and measures the cost of performing
 * a homomorphic addition on their ciphertexts in each benchmark iteration.
 *
 * @param state Benchmark state used to control and report iterations.
 */
static void BM_HomomorphicAdd(benchmark::State& state) {
  EnsureInitialized(state);
  Polynomial poly1({1, 2, 3, 4});
  Polynomial poly2({5, 6, 7, 8});
  auto enc1 = EncryptedPolynomial::Encrypt(poly1, g_keys.public_key, *g_fhe_ctx).value();
  auto enc2 = EncryptedPolynomial::Encrypt(poly2, g_keys.public_key, *g_fhe_ctx).value();
  
  for (auto _ : state) {
    auto result = enc1.Add(enc2, *g_fhe_ctx);
    benchmark::DoNotOptimize(result);
  }
}
BENCHMARK(BM_HomomorphicAdd);

/**
 * @brief Benchmarks homomorphic subtraction of two encrypted polynomials.
 *
 * Measures the time to subtract one ciphertext from another using the shared
 * FHE context and key pair. The benchmark encrypts two small polynomials once
 * and then repeatedly performs the ciphertext subtraction operation.
 *
 * Note: the benchmark is skipped if the shared FHE context or keys fail to initialize.
 *
 * @param state Benchmark state provided by Google Benchmark.
 */
static void BM_HomomorphicSubtract(benchmark::State& state) {
  EnsureInitialized(state);
  Polynomial poly1({10, 20, 30, 40});
  Polynomial poly2({1, 2, 3, 4});
  auto enc1 = EncryptedPolynomial::Encrypt(poly1, g_keys.public_key, *g_fhe_ctx).value();
  auto enc2 = EncryptedPolynomial::Encrypt(poly2, g_keys.public_key, *g_fhe_ctx).value();
  
  for (auto _ : state) {
    auto result = enc1.Subtract(enc2, *g_fhe_ctx);
    benchmark::DoNotOptimize(result);
  }
}
BENCHMARK(BM_HomomorphicSubtract);

/**
 * @brief Benchmarks homomorphic multiplication of an encrypted polynomial by a scalar.
 *
 * Repeatedly multiplies a pre-encrypted polynomial by the scalar 5 using the shared FHE
 * context and records performance.
 *
 * @param state Benchmark state provided by Google Benchmark.
 */
static void BM_ScalarMultiply(benchmark::State& state) {
  EnsureInitialized(state);
  Polynomial poly({1, 2, 3, 4});
  auto enc = EncryptedPolynomial::Encrypt(poly, g_keys.public_key, *g_fhe_ctx).value();
  
  for (auto _ : state) {
    auto result = enc.MultiplyScalar(5, *g_fhe_ctx);
    benchmark::DoNotOptimize(result);
  }
}
BENCHMARK(BM_ScalarMultiply);

/**
 * @brief Measures the cost of rotating an encrypted polynomial by a fixed offset.
 *
 * Repeatedly rotates a pre-encrypted polynomial by 2 positions and prevents the result
 * from being optimized away to measure the homomorphic rotation performance.
 *
 * @param state Benchmark state provided by the Google Benchmark framework.
 */
static void BM_Rotation(benchmark::State& state) {
  EnsureInitialized(state);
  Polynomial poly({1, 2, 3, 4, 5, 6, 7, 8});
  auto enc = EncryptedPolynomial::Encrypt(poly, g_keys.public_key, *g_fhe_ctx).value();
  
  for (auto _ : state) {
    auto result = enc.Rotate(2, *g_fhe_ctx);
    benchmark::DoNotOptimize(result);
  }
}
BENCHMARK(BM_Rotation);

/**
 * @brief Benchmarks the cost of projecting an encrypted polynomial to a character.
 *
 * Measures the time required to perform a single character projection operation
 * (EncryptedPolynomial::ProjectToCharacter) on a pre-encrypted polynomial using
 * the shared FHE context and public key.
 *
 * @param state Google Benchmark state used to control iterations and report results.
 */
static void BM_CharacterProjection(benchmark::State& state) {
  EnsureInitialized(state);
  Polynomial poly({1, 2, 3, 4, 5, 6, 7, 8});
  auto enc = EncryptedPolynomial::Encrypt(poly, g_keys.public_key, *g_fhe_ctx).value();
  
  for (auto _ : state) {
    auto result = enc.ProjectToCharacter(0, *g_fhe_ctx);
    benchmark::DoNotOptimize(result);
  }
}
BENCHMARK(BM_CharacterProjection);

/**
 * @brief Measures end-to-end performance of encrypting, operating on, and decrypting a polynomial.
 *
 * Runs a full cycle each iteration: encrypt the plaintext polynomial, multiply the ciphertext by 2,
 * then decrypt the result to measure combined cost of encryption, homomorphic operation, and decryption.
 *
 * @param state Benchmark state used to control loop iterations and record timing.
 */
static void BM_FullCycle(benchmark::State& state) {
  EnsureInitialized(state);
  Polynomial poly({1, 2, 3, 4});
  
  for (auto _ : state) {
    auto enc = EncryptedPolynomial::Encrypt(poly, g_keys.public_key, *g_fhe_ctx).value();
    auto doubled = enc.MultiplyScalar(2, *g_fhe_ctx).value();
    auto dec = doubled.Decrypt(g_keys.private_key, *g_fhe_ctx);
    benchmark::DoNotOptimize(dec);
  }
}
BENCHMARK(BM_FullCycle);

}  // namespace f2chat

BENCHMARK_MAIN();