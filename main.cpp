#include <assert.h>
#include <fmt/base.h>
#include <fmt/ranges.h>
#include <mbedtls/sha256.h>

#include <filesystem>

#include "apksig/apksig.hpp"

namespace {

std::array<uint8_t, 32> sha256(const uint8_t *in, size_t size) {
  std::array<uint8_t, 32> out;
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, in, size);
  mbedtls_sha256_finish(&ctx, out.data());
  mbedtls_sha256_free(&ctx);
  return out;
}

std::string hexstr(const uint8_t *p, size_t size) {
  std::string out;
  for (size_t i = 0; i < size; i++) {
    out.append(fmt::format("{:02x}", p[i]));
  }
  return out;
}
}  // namespace

int main(int argc, const char *argv[]) {
  assert(argc == 2);

  const char *fpath = argv[1];
  apksig::siginfo siginfo{std::filesystem::path(fpath)};
  siginfo.parse();
  fmt::println("has v2 block: {}", siginfo.has_v2_block());
  fmt::println("has v3 block: {}", siginfo.has_v3_block());

  const auto v2_block = siginfo.get_v2_block();
  fmt::println("num signers: {}", v2_block.signers.size());

  for (const auto &signer : v2_block.signers) {
    const auto certificates = signer.signed_data.certificates;
    for (const auto &certificate : certificates) {
      const auto cert_hash = sha256(certificate.data(), certificate.size());
      fmt::println("cert hash: {}", hexstr(cert_hash.data(), cert_hash.size()));
    }
    const auto pk_hash = sha256(signer.public_key.data(), signer.public_key.size());
    fmt::println("pk sha256: {}", hexstr(pk_hash.data(), pk_hash.size()));
  }

  return 0;
}