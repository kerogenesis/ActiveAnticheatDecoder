#pragma once

// Compatibility layer for UltimateProxyDLL's OBF/MAKEOBF hooks.
//
// The upstream header expects an external obfuscation library to define these
// macros. Keep that integration point, but make it real enough for this proxy:
// string literals are encoded at compile time and decoded only when used.
// Release builds also compile debugger output calls down to a no-op unless
// AA_PROXY_ENABLE_DEBUG_LOG is explicitly enabled.

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>

#ifndef AA_PROXY_ENABLE_DEBUG_LOG
#define AA_PROXY_ENABLE_DEBUG_LOG 0
#endif

#if !AA_PROXY_ENABLE_DEBUG_LOG
#define OutputDebugStringA(...) ((void)0)
#endif

namespace aa_obf {
constexpr std::uint32_t mix(std::uint32_t value) {
    value ^= value >> 16;
    value *= 0x7FEB352Du;
    value ^= value >> 15;
    value *= 0x846CA68Bu;
    value ^= value >> 16;
    return value;
}

constexpr char key_byte(std::uint32_t seed, std::size_t index) {
    return static_cast<char>(mix(seed + static_cast<std::uint32_t>(index * 0x9E37u)) >> 16);
}

template <std::size_t N, std::uint32_t Seed>
class obfuscated_literal {
  public:
    constexpr explicit obfuscated_literal(const char (&literal)[N])
        : encrypted_{}, decoded_{}, decoded_ready_(false) {
        for (std::size_t i = 0; i < N; ++i) {
            encrypted_[i] = static_cast<char>(literal[i] ^ key_byte(Seed, i));
        }
    }

    std::string str() const { return std::string(c_str()); }

    const char* c_str() const {
        if (!decoded_ready_) {
            for (std::size_t i = 0; i < N; ++i) {
                decoded_[i] = static_cast<char>(encrypted_[i] ^ key_byte(Seed, i));
            }
            decoded_ready_ = true;
        }
        return decoded_;
    }

    operator const char*() const { return c_str(); }

  private:
    char encrypted_[N];
    mutable char decoded_[N];
    mutable bool decoded_ready_;
};

template <std::uint32_t Seed, std::size_t N>
constexpr auto make_obfuscated(const char (&literal)[N]) {
    return obfuscated_literal<N, Seed>(literal);
}

template <std::size_t N, std::uint32_t Seed>
std::ostream& operator<<(std::ostream& stream, const obfuscated_literal<N, Seed>& literal) {
    return stream << literal.c_str();
}

template <std::size_t N, std::uint32_t Seed>
std::string operator+(const obfuscated_literal<N, Seed>& lhs, const std::string& rhs) {
    return lhs.str() + rhs;
}

template <std::size_t N, std::uint32_t Seed>
std::string operator+(const obfuscated_literal<N, Seed>& lhs, const char* rhs) {
    return lhs.str() + rhs;
}

template <std::size_t N, std::uint32_t Seed>
std::string operator+(const std::string& lhs, const obfuscated_literal<N, Seed>& rhs) {
    return lhs + rhs.str();
}

template <std::size_t N, std::uint32_t Seed>
std::string operator+(const char* lhs, const obfuscated_literal<N, Seed>& rhs) {
    return std::string(lhs) + rhs.str();
}
} // namespace aa_obf

#define AA_OBF_SEED                                                                              \
    (0xA5A55A5Au ^ (static_cast<std::uint32_t>(__LINE__) * 0x045D9F3Bu) ^                       \
     (static_cast<std::uint32_t>(__COUNTER__) * 0x119DE1F3u))

#ifndef MAKEOBF
#define MAKEOBF(text) (::aa_obf::make_obfuscated<AA_OBF_SEED>(text))
#endif

#ifndef OBF
#define OBF(text)                                                                                \
    ([]() -> const char* {                                                                       \
        static auto literal = MAKEOBF(text);                                                     \
        return literal.c_str();                                                                  \
    }())
#endif
