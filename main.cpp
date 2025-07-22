#include <assert.h>
#include <fmt/base.h>

#include <filesystem>

#include "apksig/apksig.hpp"

int main(int argc, const char *argv[]) {
  assert(argc == 2);

  const char *fpath = argv[1];
  apksig::siginfo siginfo{std::filesystem::path(fpath)};
  siginfo.parse();
  fmt::println("has v2 block: {}", siginfo.has_v2_block());
  fmt::println("has v3 block: {}", siginfo.has_v3_block());
  siginfo.parse_v2_block();

  return 0;
}