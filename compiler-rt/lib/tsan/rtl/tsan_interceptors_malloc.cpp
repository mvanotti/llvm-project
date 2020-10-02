//===-- tsan_interceptors_malloc.cpp ---------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
// FIXME: move as many interceptors as possible into
// sanitizer_common/sanitizer_common_interceptors.inc
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_errno.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_linux.h"
#include "sanitizer_common/sanitizer_platform_limits_netbsd.h"
#include "sanitizer_common/sanitizer_platform_limits_posix.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_tls_get_addr.h"
#include "interception/interception.h"
#include "tsan_interceptors.h"
#include "tsan_interface.h"
#include "tsan_platform.h"
#include "tsan_suppressions.h"
#include "tsan_rtl.h"
#include "tsan_mman.h"
#include "tsan_fd.h"

#include <stdarg.h>

using namespace __tsan;

DECLARE_REAL_AND_INTERCEPTOR(void *, malloc, uptr size)
DECLARE_REAL_AND_INTERCEPTOR(void, free, void *ptr)
#if !SANITIZER_FREEBSD && !SANITIZER_ANDROID && !SANITIZER_NETBSD
extern "C" int mallopt(int param, int value);
#endif
// void *const MAP_FAILED = (void*)-1;
// const int MAP_FIXED = 0x10;
typedef long long_t;
typedef __sanitizer::u16 mode_t;

#define COMMON_INTERCEPTOR_NOTHING_IS_INITIALIZED \
  (cur_thread_init(), !cur_thread()->is_inited)

#define TSAN_INTERCEPT(func) INTERCEPT_FUNCTION(func)
#if SANITIZER_FREEBSD
# define TSAN_INTERCEPT_VER(func, ver) INTERCEPT_FUNCTION(func)
# define TSAN_MAYBE_INTERCEPT_NETBSD_ALIAS(func)
# define TSAN_MAYBE_INTERCEPT_NETBSD_ALIAS_THR(func)
#elif SANITIZER_NETBSD
# define TSAN_INTERCEPT_VER(func, ver) INTERCEPT_FUNCTION(func)
# define TSAN_MAYBE_INTERCEPT_NETBSD_ALIAS(func) \
         INTERCEPT_FUNCTION(__libc_##func)
# define TSAN_MAYBE_INTERCEPT_NETBSD_ALIAS_THR(func) \
         INTERCEPT_FUNCTION(__libc_thr_##func)
#else
# define TSAN_INTERCEPT_VER(func, ver) INTERCEPT_FUNCTION_VER(func, ver)
# define TSAN_MAYBE_INTERCEPT_NETBSD_ALIAS(func)
# define TSAN_MAYBE_INTERCEPT_NETBSD_ALIAS_THR(func)
#endif

#define READ_STRING_OF_LEN(thr, pc, s, len, n)                 \
  MemoryAccessRange((thr), (pc), (uptr)(s),                         \
    common_flags()->strict_string_checks ? (len) + 1 : (n), false)

#define READ_STRING(thr, pc, s, n)                             \
    READ_STRING_OF_LEN((thr), (pc), (s), internal_strlen(s), (n))


#if !SANITIZER_MAC
TSAN_INTERCEPTOR(void*, malloc, uptr size) {
  if (in_symbolizer())
    return InternalAlloc(size);
  void *p = 0;
  {
    SCOPED_INTERCEPTOR_RAW(malloc, size);
    p = user_alloc(thr, pc, size);
  }
  invoke_malloc_hook(p, size);
  return p;
}

#if !SANITIZER_FUCHSIA
TSAN_INTERCEPTOR(void*, __libc_memalign, uptr align, uptr sz) {
  SCOPED_TSAN_INTERCEPTOR(__libc_memalign, align, sz);
  return user_memalign(thr, pc, align, sz);
}
#endif  //  !SANITIZER_FUCHSIA

TSAN_INTERCEPTOR(void*, calloc, uptr size, uptr n) {
  if (in_symbolizer())
    return InternalCalloc(size, n);
  void *p = 0;
  {
    SCOPED_INTERCEPTOR_RAW(calloc, size, n);
    p = user_calloc(thr, pc, size, n);
  }
  invoke_malloc_hook(p, n * size);
  return p;
}

TSAN_INTERCEPTOR(void*, realloc, void *p, uptr size) {
  if (in_symbolizer())
    return InternalRealloc(p, size);
  if (p)
    invoke_free_hook(p);
  {
    SCOPED_INTERCEPTOR_RAW(realloc, p, size);
    p = user_realloc(thr, pc, p, size);
  }
  invoke_malloc_hook(p, size);
  return p;
}

TSAN_INTERCEPTOR(void*, reallocarray, void *p, uptr size, uptr n) {
  if (in_symbolizer())
    return InternalReallocArray(p, size, n);
  if (p)
    invoke_free_hook(p);
  {
    SCOPED_INTERCEPTOR_RAW(reallocarray, p, size, n);
    p = user_reallocarray(thr, pc, p, size, n);
  }
  invoke_malloc_hook(p, size);
  return p;
}

TSAN_INTERCEPTOR(void, free, void *p) {
  if (p == 0)
    return;
  if (in_symbolizer())
    return InternalFree(p);
  invoke_free_hook(p);
  SCOPED_INTERCEPTOR_RAW(free, p);
  user_free(thr, pc, p);
}

TSAN_INTERCEPTOR(void, cfree, void *p) {
  if (p == 0)
    return;
  if (in_symbolizer())
    return InternalFree(p);
  invoke_free_hook(p);
  SCOPED_INTERCEPTOR_RAW(cfree, p);
  user_free(thr, pc, p);
}

TSAN_INTERCEPTOR(uptr, malloc_usable_size, void *p) {
  SCOPED_INTERCEPTOR_RAW(malloc_usable_size, p);
  return user_alloc_usable_size(p);
}
#endif

#if !SANITIZER_FUCHSIA
// Zero out addr if it points into shadow memory and was provided as a hint
// only, i.e., MAP_FIXED is not set.
static bool fix_mmap_addr(void **addr, long_t sz, int flags) {
  if (*addr) {
    if (!IsAppMem((uptr)*addr) || !IsAppMem((uptr)*addr + sz - 1)) {
      if (flags & MAP_FIXED) {
        errno = errno_EINVAL;
        return false;
      } else {
        *addr = 0;
      }
    }
  }
  return true;
}

template <class Mmap>
static void *mmap_interceptor(ThreadState *thr, uptr pc, Mmap real_mmap,
                              void *addr, SIZE_T sz, int prot, int flags,
                              int fd, OFF64_T off) {
  if (!fix_mmap_addr(&addr, sz, flags)) return MAP_FAILED;
  void *res = real_mmap(addr, sz, prot, flags, fd, off);
  if (res != MAP_FAILED) {
    if (fd > 0) FdAccess(thr, pc, fd);
    MemoryRangeImitateWriteOrResetRange(thr, pc, (uptr)res, sz);
  }
  return res;
}

TSAN_INTERCEPTOR(int, munmap, void *addr, long_t sz) {
  SCOPED_TSAN_INTERCEPTOR(munmap, addr, sz);
  UnmapShadow(thr, (uptr)addr, sz);
  int res = REAL(munmap)(addr, sz);
  return res;
}
#endif  //  !SANITIZER_FUCHSIA

#if SANITIZER_LINUX || SANITIZER_FUCHSIA
TSAN_INTERCEPTOR(void*, memalign, uptr align, uptr sz) {
  SCOPED_INTERCEPTOR_RAW(memalign, align, sz);
  return user_memalign(thr, pc, align, sz);
}
#define TSAN_MAYBE_INTERCEPT_MEMALIGN TSAN_INTERCEPT(memalign)
#else
#define TSAN_MAYBE_INTERCEPT_MEMALIGN
#endif

#if !SANITIZER_MAC
TSAN_INTERCEPTOR(void*, aligned_alloc, uptr align, uptr sz) {
  if (in_symbolizer())
    return InternalAlloc(sz, nullptr, align);
  SCOPED_INTERCEPTOR_RAW(aligned_alloc, align, sz);
  return user_aligned_alloc(thr, pc, align, sz);
}

TSAN_INTERCEPTOR(void*, valloc, uptr sz) {
  if (in_symbolizer())
    return InternalAlloc(sz, nullptr, GetPageSizeCached());
  SCOPED_INTERCEPTOR_RAW(valloc, sz);
  return user_valloc(thr, pc, sz);
}
#endif

#if SANITIZER_LINUX || SANITIZER_FUCHSIA
TSAN_INTERCEPTOR(void*, pvalloc, uptr sz) {
  if (in_symbolizer()) {
    uptr PageSize = GetPageSizeCached();
    sz = sz ? RoundUpTo(sz, PageSize) : PageSize;
    return InternalAlloc(sz, nullptr, PageSize);
  }
  SCOPED_INTERCEPTOR_RAW(pvalloc, sz);
  return user_pvalloc(thr, pc, sz);
}
#define TSAN_MAYBE_INTERCEPT_PVALLOC TSAN_INTERCEPT(pvalloc)
#else
#define TSAN_MAYBE_INTERCEPT_PVALLOC
#endif

#if !SANITIZER_MAC
TSAN_INTERCEPTOR(int, posix_memalign, void **memptr, uptr align, uptr sz) {
  if (in_symbolizer()) {
    void *p = InternalAlloc(sz, nullptr, align);
    if (!p)
      return errno_ENOMEM;
    *memptr = p;
    return 0;
  }
  SCOPED_INTERCEPTOR_RAW(posix_memalign, memptr, align, sz);
  return user_posix_memalign(thr, pc, memptr, align, sz);
}
#endif
