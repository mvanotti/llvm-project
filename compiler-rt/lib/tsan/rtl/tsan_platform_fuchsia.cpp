//===-- tsan_platform_fuchsia.cpp -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of ThreadSanitizer (TSan), a race detector.
//
// Fuchsia-specific code.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_stackdepot.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_symbolizer.h"
#include "sanitizer_common/sanitizer_tls_get_addr.h"
#if SANITIZER_FUCHSIA

#include "tsan_platform.h"
#include "tsan_interceptors.h"
#include "tsan_rtl.h"

#include <stdlib.h>
#include <pthread.h>

#include <zircon/sanitizer.h>
// TODO(mvanotti): Remove after sanitizer.h declares this.
extern "C" void __sanitizer_zero_memory(uintptr_t base, size_t addr);

namespace __tsan {

void FlushShadowMemory() {}

void WriteMemoryProfile(char *buf, uptr buf_size, uptr nthread, uptr nlive) {}

// All of this has been done already by __tsan_early_init in fuchsia.
void InitializePlatformEarly() {}
void InitializePlatform() {}
void ReplaceSystemMalloc() {}
void InitializeShadowMemory() {}
void InitializeLibIgnore() { }

void ImitateTlsWrite(ThreadState *thr, uptr tls_addr, uptr tls_size) { /* TODO */ }

void ProcessPendingSignals(ThreadState *thr) {}

void ZeroPages(uptr addr, uptr size) {
  __sanitizer_zero_memory(addr, size);
}

void DontNeedShadowFor(uptr addr, uptr size) {
  uptr shadow_beg = MemToShadow(addr);
  uptr shadow_end = MemToShadow(addr + size);
  __sanitizer_zero_memory(shadow_beg, shadow_end - shadow_beg);
}

struct ThreadParam {
  uptr pc;
  atomic_uintptr_t flag;
  atomic_uintptr_t refcnt;
  int tid;

  void Unref();
};

void ThreadParam::Unref() {
  int remaining = atomic_fetch_sub(&this->refcnt, 1, memory_order_seq_cst);
  if (remaining == 1) {
    delete this;
  }
}

static void *BeforeThreadCreateHook(uptr user_id, bool detached,
                                    const char *name, uptr stack_bottom,
                                    uptr stack_size) {
  cur_thread_init();
  ThreadState *thr = cur_thread();
  const uptr pc = StackTrace::GetCurrentPc();
  ThreadIgnoreBegin(thr, pc);
  ThreadParam *p = new ThreadParam();
  p->pc = pc;
  atomic_store(&p->refcnt, detached ? 1 : 2, memory_order_acquire);
  CHECK_EQ(atomic_load(&p->flag, memory_order_acquire), 0);

  return p; // The other hooks need this value.
}

static void ThreadCreateHook(void *hook, uptr os_id, bool aborted) {
  cur_thread_init();
  ThreadState *thr = cur_thread();
  ThreadParam *p = static_cast<ThreadParam *>(hook);
  CHECK_NE(p, nullptr);

  ThreadIgnoreEnd(thr, p->pc);
  if (aborted) {
    delete p;
    return;
  }
  int tid = ThreadCreate(thr, p->pc, os_id, false);
  CHECK_NE(tid, 0);
  p->tid = tid;
  atomic_store(&p->flag, 1, memory_order_release);
  while (atomic_load(&p->flag, memory_order_acquire) != 0)
    internal_sched_yield();
}

static void ThreadStartHook(void *hook, uptr os_id) {
  cur_thread_init();
  ThreadState *thr = cur_thread();
  ThreadParam *p = static_cast<ThreadParam *>(hook);
  CHECK_NE(p, nullptr);
  while (atomic_load(&p->flag, memory_order_acquire) == 0)
    internal_sched_yield();
  int tid = p->tid;
  Processor *proc = ProcCreate();
  ProcWire(proc, thr);
  ThreadStart(thr, tid, GetTid(), ThreadType::Regular);
  atomic_store(&p->flag, 0, memory_order_release); // We are done here.
}

static void ThreadExitHook(void *hook, uptr os_id) {
  ThreadState *thr = cur_thread();
  Processor *proc = thr->proc();
  ThreadFinish(thr);
  ProcUnwire(proc, thr);
  ProcDestroy(proc);
  DTLS_Destroy();
  // cur_thread_finalize(); questionmark
  ThreadParam *t = static_cast<ThreadParam *>(hook);
  t->Unref();
}

static void ThreadJoinHook(void *hook, uptr os_id) {
  ThreadState *thr = cur_thread();
  const uptr pc = StackTrace::GetCurrentPc();
  ThreadJoin(thr, pc, static_cast<ThreadParam *>(hook)->tid);
  ThreadParam *t = static_cast<ThreadParam *>(hook);
  t->Unref();
}

static void ThreadDetachHook(void *hook) {
  ThreadState *thr = cur_thread();
  const uptr pc = StackTrace::GetCurrentPc();
  ThreadParam *t = static_cast<ThreadParam *>(hook);
  ThreadDetach(thr, pc, t->tid);

  t->Unref();
}

void InitializeInterceptors() {} // NOBODY can intercept fuchsia.
LibIgnore *libignore() { return nullptr; }

ScopedInterceptor::ScopedInterceptor(ThreadState *thr, const char *fname,
                                     uptr pc)
    : thr_(thr), pc_(pc), in_ignored_lib_(false), ignoring_(false) {}

ScopedInterceptor::~ScopedInterceptor() {}

void ScopedInterceptor::EnableIgnores() {
(void) thr_; (void) pc_; (void) in_ignored_lib_; (void) ignoring_;}

void ScopedInterceptor::DisableIgnores() {}

void PlatformCleanUpThreadState(ThreadState *thr) {} 

}  // namespace __tsan

void *__sanitizer_before_thread_create_hook(thrd_t thread, bool detached,
                                            const char *name, void *stack_base,
                                            size_t stack_size) {
  return __tsan::BeforeThreadCreateHook(
      reinterpret_cast<__sanitizer::uptr>(thread), detached, name,
      reinterpret_cast<__sanitizer::uptr>(stack_base), stack_size);
}

void __sanitizer_thread_create_hook(void *hook, thrd_t thread, int error) {
  __tsan::ThreadCreateHook(hook, reinterpret_cast<__sanitizer::uptr>(thread), error != thrd_success);
}

void __sanitizer_thread_start_hook(void *hook, thrd_t self) {
  __tsan::ThreadStartHook(hook, reinterpret_cast<__sanitizer::uptr>(self));
}

void __sanitizer_thread_exit_hook(void *hook, thrd_t self) {
  __tsan::ThreadExitHook(hook, reinterpret_cast<__sanitizer::uptr>(self));
}

extern "C" __attribute__((__visibility__("default"))) void __sanitizer_thread_join_hook(void* hook, thrd_t self) {
  __tsan::ThreadJoinHook(hook, reinterpret_cast<__sanitizer::uptr>(self));
}

extern "C" __attribute__((__visibility__("default"))) void __sanitizer_thread_detach_hook(void *hook) {
  __tsan::ThreadDetachHook(hook);
}
#endif  // SANITIZER_FUCHSIA
