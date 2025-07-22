#include "apksig/apksig.hpp"

#include <fmt/base.h>
#include <fmt/ranges.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <ios>
#include <iterator>
#include <type_traits>
#include <vector>

namespace {

template <class ForwardIt>
std::streampos reverse_find_bytes(std::istream& is, ForwardIt pat_first, ForwardIt pat_last,
                                  std::streampos start = -1) {
  using value_type = typename std::iterator_traits<ForwardIt>::value_type;
  static_assert(sizeof(value_type) == 1,
                "The value type of ForwardIt should be byte like (std::byte, char, uint8_t etc.)");

  if (start == -1) {
    is.seekg(0, std::ios_base::end);
  } else {
    is.seekg(start);
  }

  const auto pat_size = std::distance(pat_first, pat_last);
  if (pat_size == 0) return -1;
  if (pat_size < 0) throw std::runtime_error("pat_first comes after pat_last");

  constexpr size_t default_window_size = 4 * 1024;  // 4KiB
  size_t window_size = std::max(default_window_size, static_cast<size_t>(pat_size));
  std::vector<std::uint8_t> window_buffer(window_size);
  std::vector<std::uint8_t> carry_buffer(static_cast<size_t>(pat_size) - 1);

  std::streampos current_pos = is.tellg();

  while (current_pos > 0) {
    const std::streampos pos = std::max(std::streampos(0), current_pos - static_cast<std::streamoff>(window_size));
    window_buffer.resize(static_cast<size_t>(current_pos - pos));
    is.seekg(pos);
    is.read(reinterpret_cast<char*>(window_buffer.data()), static_cast<std::streamsize>(window_buffer.size()));
    window_buffer.insert(window_buffer.end(), carry_buffer.cbegin(), carry_buffer.cend());

    for (auto it = window_buffer.crbegin() + pat_size; it != window_buffer.crend(); it++) {
      if (std::equal(pat_first, pat_last, it.base() - 1)) {
        return pos + static_cast<std::streamoff>(std::distance(window_buffer.cbegin(), it.base() - 1));
      }
    }

    carry_buffer.assign(window_buffer.cbegin(), window_buffer.cbegin() + pat_size - 1);
    current_pos = pos;
  }

  return -1;
}

template <size_t N, class T = uint8_t>
std::array<T, N> read_into_array(std::istream& is) {
  std::array<T, N> items_read;
  is.read(reinterpret_cast<char*>(items_read.data()), std::streamsize(N));
  return items_read;
}

template <class T>
T le_to_host(const uint8_t* p) noexcept {
  static_assert(std::is_unsigned_v<T> && std::is_integral_v<T>, "T must be a unsigned integral type");
  static_assert(sizeof(T) <= 8, "Supports up to 64-bit integers");

  T v = 0;
  for (std::size_t i = 0; i < sizeof(T); i++) {
    v |= static_cast<T>(p[i]) << (8 * i);
  }
  return v;
}

template <class T>
T read_le(std::istream& is) {
  const auto buf = read_into_array<sizeof(T)>(is);
  return le_to_host<T>(buf.data());
}

struct span {
  uint32_t len;
  const uint8_t* data;
  const uint8_t* begin() const noexcept { return data; }
  const uint8_t* end() const noexcept { return data + len; }
};

span parse_len_prefix_value(const uint8_t* p) {
  const auto len = le_to_host<uint32_t>(p);
  const uint8_t* value = p + sizeof(len);
  return {len, value};
}

std::vector<span> parse_len_prefix_seq(const uint8_t* first, const uint8_t* last) {
  std::vector<span> out;
  while (first < last) {
    if (last - first < 4) throw std::runtime_error("truncated sequence");
    const auto [len, data] = parse_len_prefix_value(first);
    if (data + len > last) throw std::runtime_error("truncated value in sequence");
    out.push_back({len, data});
    first = data + len;
  }
  return out;
}

std::vector<span> parse_len_prefix_seq(const span s) { return parse_len_prefix_seq(s.data, s.data + s.len); }

std::array<uint8_t, 32> sha256(const uint8_t* in, size_t size) {
  std::array<uint8_t, 32> out;
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, in, size);
  mbedtls_sha256_finish(&ctx, out.data());
  mbedtls_sha256_free(&ctx);
  return out;
}

std::string hexstr(const uint8_t* p, size_t size) {
  std::string out;
  for (size_t i = 0; i < size; i++) {
    out.append(fmt::format("{:02x}", p[i]));
  }
  return out;
}

}  // namespace

namespace apksig {

siginfo::siginfo(const std::filesystem::path& apk_fpath) : ifs_(apk_fpath, std::ios_base::in | std::ios_base::binary) {
  ifs_.exceptions(std::ios_base::failbit | std::ios_base::badbit);
}

void siginfo::parse() {
  const auto eocd_magic_pos = reverse_find_bytes(ifs_, eocd_magic.cbegin(), eocd_magic.cend());
  if (eocd_magic_pos == -1) {
    throw parse_error("Not a zip file, could not find EOCD Magic");
  }

  const auto offset_of_start_of_cd_pos = eocd_magic_pos + static_cast<std::streamoff>(16);
  ifs_.seekg(offset_of_start_of_cd_pos);
  const auto offset_of_start_of_cd = read_le<uint32_t>(ifs_);
  ifs_.seekg(offset_of_start_of_cd, std::ios_base::beg);

  const auto start_of_cd_pos = ifs_.tellg();
  const auto apk_sig_magic_pos = start_of_cd_pos - static_cast<std::streamoff>(16);
  ifs_.seekg(apk_sig_magic_pos);
  const auto magic = read_into_array<16>(ifs_);
  if (!std::equal(magic.cbegin(), magic.cend(), apk_magic.cbegin(), apk_magic.cend())) {
    throw parse_error("APK signing block magic not found where expected");
  }

  const auto apk_sig_size_of_block_pos = apk_sig_magic_pos - static_cast<std::streampos>(8);
  ifs_.seekg(apk_sig_size_of_block_pos);
  const auto apk_sig_size_of_block = read_le<uint64_t>(ifs_);

  const auto apk_sig_id_val_pairs_pos = start_of_cd_pos - static_cast<std::streamoff>(apk_sig_size_of_block);

  for (auto i = apk_sig_id_val_pairs_pos; i < apk_sig_size_of_block_pos;) {
    ifs_.seekg(i);
    const auto pair_len = read_le<uint64_t>(ifs_);
    const auto id = read_le<uint32_t>(ifs_);
    // REFACTOR Remove duplciation of reading bytes into v2/v3 vector
    if (id == v2_id) {
      const auto value_len = read_le<uint32_t>(ifs_);
      v2_block_buf_.resize(value_len);
      ifs_.read(reinterpret_cast<char*>(v2_block_buf_.data()), static_cast<std::streamsize>(v2_block_buf_.size()));
    } else if (id == v3_id) {
      const auto value_len = read_le<uint32_t>(ifs_);
      v3_block_buf_.resize(value_len);
      ifs_.read(reinterpret_cast<char*>(v3_block_buf_.data()), static_cast<std::streamsize>(v3_block_buf_.size()));
    }

    i += static_cast<std::streamoff>(pair_len + 8);
  }
}

void siginfo::parse_v2_block() const {
  const uint8_t* signer_seq_start = v2_block_buf_.data();
  const uint8_t* signer_seq_end = signer_seq_start + v2_block_buf_.size();

  const auto signer_spans = parse_len_prefix_seq(signer_seq_start, signer_seq_end);

  for (const auto signer_span : signer_spans) {
    signed_data signed_data;

    const auto signed_data_span = parse_len_prefix_value(signer_span.data);
    const auto signatures_seq_span = parse_len_prefix_value(signed_data_span.data + signed_data_span.len);
    const auto public_key_span = parse_len_prefix_value(signatures_seq_span.data + signatures_seq_span.len);

    // signed data parsing
    const auto digests_seq_span = parse_len_prefix_value(signed_data_span.data);
    const auto certificates_seq_span = parse_len_prefix_value(digests_seq_span.data + digests_seq_span.len);
    const auto add_attr_seq_span = parse_len_prefix_value(certificates_seq_span.data + certificates_seq_span.len);

    std::vector<digest> digests;
    for (const auto digest_span: parse_len_prefix_seq(digests_seq_span)) {
      const auto sig_algo_id = le_to_host<uint32_t>(digest_span.data);
      const auto digest_data_span = parse_len_prefix_value(digest_span.data + sizeof(sig_algo_id));
      digests.emplace_back(sig_algo_id, digest_data_span.begin(), digest_data_span.end());
    }

    std::vector<certificate> certificates;
    for (const auto certificate_span : parse_len_prefix_seq(certificates_seq_span)) {
      certificates.emplace_back(certificate_span.begin(), certificate_span.end());
    }

    std::vector<signature> signatures;
    for (const auto signature_span : parse_len_prefix_seq(signatures_seq_span)) {
      const auto sig_algo_id = le_to_host<uint32_t>(signature_span.data);
      const auto sig_span = parse_len_prefix_value(signature_span.data + sizeof(sig_algo_id));
      signatures.emplace_back(sig_algo_id, sig_span.begin(), sig_span.end());
    }

    const auto pk_sha256 = sha256(public_key_span.data, public_key_span.len);
    fmt::println("pk_sha256: {}", hexstr(pk_sha256.data(), pk_sha256.size()));

    fmt::println("signer span len: {}", signer_span.len);
    fmt::println("signed data span len: {}", signed_data_span.len);
    fmt::println("signatures seq span len: {}", signatures_seq_span.len);
    fmt::println("public key span: {}", public_key_span.len);
    fmt::println("-------------------");
  }
}

}  // namespace apksig
