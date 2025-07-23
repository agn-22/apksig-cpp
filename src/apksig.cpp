#include "apksig/apksig.hpp"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <ios>
#include <istream>
#include <iterator>
#include <stdexcept>
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

std::vector<uint8_t> read_into_vector(std::istream& is, size_t n) {
  std::vector<uint8_t> out(n);
  is.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(n));
  return out;
}

template <class F>
auto parse_len_prefixed_seq(uint32_t seq_len, std::istream& is, F f) {
  std::vector<std::invoke_result_t<F, uint32_t, std::istream&>> out;
  uint32_t parsed_len = 0;
  while (parsed_len < seq_len) {
    const auto len = read_le<uint32_t>(is);
    out.push_back(f(len, is));
    parsed_len += sizeof(len) + len;
    if (parsed_len > seq_len) throw std::runtime_error("Incomplete sequence");
  }
  return out;
}

apksig::digest parse_digest(uint32_t len, std::istream& is) {
  const auto sig_algo_id = read_le<uint32_t>(is);
  const auto digest_data_len = read_le<uint32_t>(is);
  const auto digest_data = read_into_vector(is, digest_data_len);
  return {sig_algo_id, digest_data};
}

apksig::certificate parse_certificate(uint32_t len, std::istream& is) { return read_into_vector(is, len); }

apksig::add_attr parse_add_attr(uint32_t len, std::istream& is) {
  const auto id = read_le<uint32_t>(is);
  const auto value_len = read_le<uint32_t>(is);
  const auto value = read_into_vector(is, value_len);
  return {id, value};
}

apksig::v2_signed_data parse_v2_signed_data(uint32_t len, std::istream& is) {
  const auto digests_seq_len = read_le<uint32_t>(is);
  const auto digests = parse_len_prefixed_seq(digests_seq_len, is, parse_digest);
  const auto certificates_seq_len = read_le<uint32_t>(is);
  const auto certificates = parse_len_prefixed_seq(certificates_seq_len, is, parse_certificate);
  const auto add_attrs_seq_len = read_le<uint32_t>(is);
  const auto add_attrs = parse_len_prefixed_seq(add_attrs_seq_len, is, parse_add_attr);
  const auto x = read_le<uint32_t>(is);
  return {digests, certificates, add_attrs};
}

apksig::signature parse_signature(uint32_t len, std::istream& is) {
  const auto sig_algo_id = read_le<uint32_t>(is);
  const auto sig_data_len = read_le<uint32_t>(is);
  const auto sig_data = read_into_vector(is, sig_data_len);
  return {sig_algo_id, sig_data};
}

apksig::public_key parse_public_key(uint32_t len, std::istream& is) { return read_into_vector(is, len); }

apksig::v2_signer parse_v2_signer(uint32_t len, std::istream& is) {
  const auto signed_data_len = read_le<uint32_t>(is);
  const auto signed_data = parse_v2_signed_data(signed_data_len, is);
  const auto signatures_seq_len = read_le<uint32_t>(is);
  const auto signatures = parse_len_prefixed_seq(signatures_seq_len, is, parse_signature);
  const auto public_key_len = read_le<uint32_t>(is);
  const auto public_key = parse_public_key(public_key_len, is);
  return {signed_data, signatures, public_key};
}

apksig::v2_block parse_v2_block(uint32_t len, std::istream& is) {
  const auto signers = parse_len_prefixed_seq(len, is, parse_v2_signer);
  return {signers};
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
      v2_block_pos_ = ifs_.tellg();
      const auto v2_block_len = read_le<uint32_t>(ifs_);
      v2_block_ = parse_v2_block(v2_block_len, ifs_);
    } else if (id == v3_id) {
      v3_block_pos_ = ifs_.tellg();
    } else if (id == v3_1_id) {
      v3_1_block_pos_ = ifs_.tellg();
    }

    i += static_cast<std::streamoff>(pair_len + 8);
  }
}

}  // namespace apksig
