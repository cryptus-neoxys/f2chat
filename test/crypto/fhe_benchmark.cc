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

// Setup function for all benchmarks
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

// Benchmark: Context creation
static void BM_FHEContextCreation(benchmark::State& state) {
  for (auto _ : state) {
    auto fhe_ctx = FHEContext::Create();
    benchmark::DoNotOptimize(fhe_ctx);
  }
}
BENCHMARK(BM_FHEContextCreation);

// Benchmark: Key generation
static void BM_KeyGeneration(benchmark::State& state) {
  EnsureInitialized(state);
  for (auto _ : state) {
    auto keys = g_fhe_ctx->GenerateKeyPair();
    benchmark::DoNotOptimize(keys);
  }
}
BENCHMARK(BM_KeyGeneration);

// Benchmark: Encryption
static void BM_Encryption(benchmark::State& state) {
  EnsureInitialized(state);
  Polynomial poly({1, 2, 3, 4, 5, 6, 7, 8});
  
  for (auto _ : state) {
    auto enc = EncryptedPolynomial::Encrypt(poly, g_keys.public_key, *g_fhe_ctx);
    benchmark::DoNotOptimize(enc);
  }
}
BENCHMARK(BM_Encryption);

// Benchmark: Decryption
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

// Benchmark: Homomorphic addition
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

// Benchmark: Homomorphic subtraction
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

// Benchmark: Scalar multiplication
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

// Benchmark: Rotation
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

// Benchmark: Character projection (most expensive operation)
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

// Benchmark: Full encrypt-operate-decrypt cycle
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
