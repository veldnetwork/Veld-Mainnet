#pragma once

#include <cstddef>
#include <cstring>
#include <string>
#include <memory>
#include <type_traits>

#ifdef _WIN32
  #include <windows.h>
  #define VELD_SECURE_BZERO(p, n) ::SecureZeroMemory((p), (n))
#else
  #include <strings.h>
  #if defined(__GLIBC__) || defined(__APPLE__) || defined(__FreeBSD__)
    #include <string.h>
    #define VELD_SECURE_BZERO(p, n) ::explicit_bzero((p), (n))
  #else
    inline void veld_secure_bzero(void* p, std::size_t n) {
        volatile unsigned char* vp = reinterpret_cast<volatile unsigned char*>(p);
        while (n--) *vp++ = 0;
    }
    #define VELD_SECURE_BZERO(p, n) veld_secure_bzero((p), (n))
  #endif
#endif

namespace veld {

template <class T>
class SecureAllocator {
public:
    using value_type = T;
    SecureAllocator() noexcept = default;
    template <class U> SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        if (n == 0) return nullptr;
        return static_cast<T*>(::operator new(n * sizeof(T)));
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (p) {
            VELD_SECURE_BZERO(p, n * sizeof(T));
            ::operator delete(p);
        }
    }

    template <class U> bool operator==(const SecureAllocator<U>&) const noexcept { return true; }
    template <class U> bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

inline bool ConstantTimeEqualsString(const char* a, std::size_t na,
                                     const char* b, std::size_t nb) {
    if (na != nb) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < na; ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

template <class A1, class A2>
inline bool ConstantTimeEquals(const std::basic_string<char, std::char_traits<char>, A1>& a,
                               const std::basic_string<char, std::char_traits<char>, A2>& b) {
    return ConstantTimeEqualsString(a.data(), a.size(), b.data(), b.size());
}

inline void WipeString(std::string& s) {
    // Wipe the allocation, not only the logical length.  Assigning a shorter
    // secret can leave bytes from the prior value between size() and
    // capacity(); clearing only size() would then return those bytes to the
    // ordinary allocator untouched.  resize(capacity()) stays within the
    // existing allocation and makes the whole region legally writable.
    const std::size_t allocated = s.capacity();
    if (allocated != 0) {
        s.resize(allocated, '\0');
        VELD_SECURE_BZERO(s.data(), s.size());
    }
    s.clear();
    s.shrink_to_fit();
}

}
