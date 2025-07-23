#pragma once

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <vector>

namespace apksig {

struct digest {
  uint32_t sig_algo_id;
  std::vector<uint8_t> digest_data;
};

using certificate = std::vector<uint8_t>;

struct add_attr {
  uint32_t id;
  std::vector<uint8_t> value;
};

struct v2_signed_data {
  std::vector<digest> digests;
  std::vector<certificate> certificates;
  std::vector<add_attr> add_attrs;
};

struct signature {
  uint32_t sig_algo_id;
  std::vector<uint8_t> signature_data;
};

using public_key = std::vector<uint8_t>;

struct v2_signer {
  v2_signed_data signed_data;
  std::vector<signature> signatures;
  public_key public_key;
};

struct v2_block {
  std::vector<v2_signer> signers;
};

class siginfo {
 public:
  siginfo(const std::filesystem::path& apk_file_path);

  bool has_v2_block() const noexcept { return v2_block_pos_ != -1; };
  bool has_v3_block() const noexcept { return v3_block_pos_ != -1; };
  bool has_v3_1_block() const noexcept { return v3_1_block_pos_ != -1; };
  void parse();
  const v2_block& get_v2_block() const noexcept { return v2_block_; }

 private:
  std::ifstream ifs_;
  std::streampos v2_block_pos_ = -1;
  std::streampos v3_block_pos_ = -1;
  std::streampos v3_1_block_pos_ = -1;
  v2_block v2_block_;

  static constexpr std::array<std::uint8_t, 4> eocd_magic{0x50, 0x4B, 0x05, 0x06};
  static constexpr std::string_view apk_magic{"APK Sig Block 42"};
  static constexpr uint32_t v2_id = 0x7109871a;
  static constexpr uint32_t v3_id = 0xf05368c0;
  static constexpr uint32_t v3_1_id = 0x1b93ad61;
};

class parse_error : public std::runtime_error {
  using std::runtime_error::runtime_error;
};

}  // namespace apksig
