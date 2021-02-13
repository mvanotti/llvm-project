//===- FuzzerUtilFuchsia.cpp - Misc utils for Fuchsia. --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// Misc utils implementation using Fuchsia/Zircon APIs.
//===----------------------------------------------------------------------===//
#include "FuzzerPlatform.h"

#if LIBFUZZER_FUCHSIA

#include "FuzzerInternal.h"
#include "FuzzerUtil.h"
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <fcntl.h>
#include <lib/fdio/fdio.h>
#include <lib/fdio/spawn.h>
#include <string>
#include <sys/select.h>
#include <thread>
#include <unistd.h>
#include <zircon/errors.h>
#include <zircon/process.h>
#include <zircon/sanitizer.h>
#include <zircon/status.h>
#include <zircon/syscalls.h>
#include <zircon/syscalls/debug.h>
#include <zircon/syscalls/exception.h>
#include <zircon/syscalls/object.h>
#include <zircon/types.h>

#include <vector>

namespace fuzzer {

// Given that Fuchsia doesn't have the POSIX signals that libFuzzer was written
// around, the general approach is to spin up dedicated threads to watch for
// each requested condition (alarm, interrupt, crash).  Of these, the crash
// handler is the most involved, as it requires resuming the crashed thread in
// order to invoke the sanitizers to get the needed state.

// Forward declaration of assembly trampoline needed to resume crashed threads.
// This appears to have external linkage to  C++, which is why it's not in the
// anonymous namespace.  The assembly definition inside MakeTrampoline()
// actually defines the symbol with internal linkage only.
void CrashTrampolineAsm() __asm__("CrashTrampolineAsm");

namespace {

// The crashing thread might not have a valid stack.
// Before executing the crash trampoline, we set up a new stack for them.
constexpr size_t kCrashStackSize = 4096 * 4;
char *CrashStack[kCrashStackSize];

// Helper function to handle Zircon syscall failures.
void ExitOnErr(zx_status_t Status, const char *Syscall) {
  if (Status != ZX_OK) {
    Printf("libFuzzer: %s failed: %s\n", Syscall,
           _zx_status_get_string(Status));
    exit(1);
  }
}

void AlarmHandler(int Seconds) {
  while (true) {
    SleepSeconds(Seconds);
    Fuzzer::StaticAlarmCallback();
  }
}

// CFAOffset is used to reference the stack pointer before entering the
// trampoline (Stack Pointer + CFAOffset = prev Stack Pointer). Before jumping
// to the trampoline we copy all the registers onto the stack. We need to make
// sure that the new stack has enough space to store all the registers.
//
// The trampoline holds CFI information regarding the registers stored in the
// stack, which is then used by the unwinder to restore them.
#if defined(__x86_64__)
// In x86_64 the crashing function might also be using the red zone (128 bytes
// on top of their rsp).
constexpr size_t CFAOffset = 128 + sizeof(zx_thread_state_general_regs_t);
#elif defined(__aarch64__)
// In aarch64 we need to always have the stack pointer aligned to 16 bytes, so we
// make sure that we are keeping that same alignment.
constexpr size_t CFAOffset = (sizeof(zx_thread_state_general_regs_t) + 15) & -(uintptr_t)16;
#endif

// For the crash handler, we need to call Fuzzer::StaticCrashSignalCallback
// without POSIX signal handlers.  To achieve this, we use an assembly function
// to add the necessary CFI unwinding information and a C function to bridge
// from that back into C++.

// FIXME: This works as a short-term solution, but this code really shouldn't be
// architecture dependent. A better long term solution is to implement remote
// unwinding and expose the necessary APIs through sanitizer_common and/or ASAN
// to allow the exception handling thread to gather the crash state directly.
//
// Alternatively, Fuchsia may in future actually implement basic signal
// handling for the machine trap signals.
#if defined(__x86_64__)
#define FOREACH_REGISTER(OP_REG, OP_NUM) \
  OP_REG(rax)                            \
  OP_REG(rbx)                            \
  OP_REG(rcx)                            \
  OP_REG(rdx)                            \
  OP_REG(rsi)                            \
  OP_REG(rdi)                            \
  OP_REG(rbp)                            \
  OP_REG(rsp)                            \
  OP_REG(r8)                             \
  OP_REG(r9)                             \
  OP_REG(r10)                            \
  OP_REG(r11)                            \
  OP_REG(r12)                            \
  OP_REG(r13)                            \
  OP_REG(r14)                            \
  OP_REG(r15)                            \
  OP_REG(rip)

#elif defined(__aarch64__)
#define FOREACH_REGISTER(OP_REG, OP_NUM) \
  OP_NUM(0)                              \
  OP_NUM(1)                              \
  OP_NUM(2)                              \
  OP_NUM(3)                              \
  OP_NUM(4)                              \
  OP_NUM(5)                              \
  OP_NUM(6)                              \
  OP_NUM(7)                              \
  OP_NUM(8)                              \
  OP_NUM(9)                              \
  OP_NUM(10)                             \
  OP_NUM(11)                             \
  OP_NUM(12)                             \
  OP_NUM(13)                             \
  OP_NUM(14)                             \
  OP_NUM(15)                             \
  OP_NUM(16)                             \
  OP_NUM(17)                             \
  OP_NUM(18)                             \
  OP_NUM(19)                             \
  OP_NUM(20)                             \
  OP_NUM(21)                             \
  OP_NUM(22)                             \
  OP_NUM(23)                             \
  OP_NUM(24)                             \
  OP_NUM(25)                             \
  OP_NUM(26)                             \
  OP_NUM(27)                             \
  OP_NUM(28)                             \
  OP_NUM(29)                             \
  OP_REG(sp)

#else
#error "Unsupported architecture for fuzzing on Fuchsia"
#endif

// Produces a CFI directive for the named or numbered register.
// The value used refers to an assembler immediate operand with the same name
// as the register (see ASM_OPERAND_REG).
#define CFI_OFFSET_REG(reg) ".cfi_offset " #reg ", %c[" #reg "]\n"
#define CFI_OFFSET_NUM(num) CFI_OFFSET_REG(x##num)

// Produces an assembler immediate operand for the named or numbered register.
// This operand contains the offset of the register relative to the CFA.
#define ASM_OPERAND_REG(reg) \
  [reg] "i"(offsetof(zx_thread_state_general_regs_t, reg)),
#define ASM_OPERAND_NUM(num)                                 \
  [x##num] "i"(offsetof(zx_thread_state_general_regs_t, r[num])),

#if defined(__x86_64__)
// DWARF Register Number Mappings for x86-64
// Extracted from https://www.uclibc.org/docs/psABI-x86_64.pdf
// System V Application Binary Interface
// AMD64 Architecture Processor Supplement
// Draft Version 0.99.7
#define REG_DWARF_NUMBER_rax 0
#define REG_DWARF_NUMBER_rbx 3
#define REG_DWARF_NUMBER_rcx 2
#define REG_DWARF_NUMBER_rdx 1
#define REG_DWARF_NUMBER_rsi 4
#define REG_DWARF_NUMBER_rdi 5
#define REG_DWARF_NUMBER_rbp 6
#define REG_DWARF_NUMBER_rsp 7
#define REG_DWARF_NUMBER_r8 8
#define REG_DWARF_NUMBER_r9 9
#define REG_DWARF_NUMBER_r10 10
#define REG_DWARF_NUMBER_r11 11
#define REG_DWARF_NUMBER_r12 12
#define REG_DWARF_NUMBER_r13 13
#define REG_DWARF_NUMBER_r14 14
#define REG_DWARF_NUMBER_r15 15
#define REG_DWARF_NUMBER_rip 16

#define REG_DWARF_NUMBER(reg) (REG_DWARF_NUMBER_ ## reg)

// Offsets for different x86-64 registers into the
// zx_thread_state_general_regs_t structure.
#define REG_OFFSET_rax 0
#define REG_OFFSET_rbx 8
#define REG_OFFSET_rcx 16
#define REG_OFFSET_rdx 24
#define REG_OFFSET_rsi 32
#define REG_OFFSET_rdi 40
#define REG_OFFSET_rbp 48
#define REG_OFFSET_rsp 56
#define REG_OFFSET_r8 64
#define REG_OFFSET_r9 72
#define REG_OFFSET_r10 80
#define REG_OFFSET_r11 88
#define REG_OFFSET_r12 96
#define REG_OFFSET_r13 104
#define REG_OFFSET_r14 112
#define REG_OFFSET_r15 120
#define REG_OFFSET_rip 128
#define REG_OFFSET(reg) (REG_OFFSET_ ## reg)

#define REG_FOREACH(OP_REG) \
  OP_REG(rax)                            \
  OP_REG(rbx)                            \
  OP_REG(rcx)                            \
  OP_REG(rdx)                            \
  OP_REG(rsi)                            \
  OP_REG(rdi)                            \
  OP_REG(rbp)                            \
  OP_REG(rsp)                            \
  OP_REG(r8)                             \
  OP_REG(r9)                             \
  OP_REG(r10)                            \
  OP_REG(r11)                            \
  OP_REG(r12)                            \
  OP_REG(r13)                            \
  OP_REG(r14)                            \
  OP_REG(r15)                            \
  OP_REG(rip)

#define CHECK_OFFSET(reg, offset) static_assert(offsetof(zx_thread_state_general_regs_t, reg) == offset, "offset mismatch");
#define REG_CHECK_OFFSET(reg) CHECK_OFFSET(reg, REG_OFFSET(reg))

REG_FOREACH(REG_CHECK_OFFSET)

#elif defined(__aarch64__)

#define REG_DWARF_NUMBER(x) (x)
#define REG_DWARF_NUMBER_LR (30)
#define REG_DWARF_NUMBER_SP (31)
#define REG_DWARF_NUMBER_PC (32)
#define REG_DWARF_NUMBER_ELR (33)

#define REG_OFFSET(x) (x * 8)
#define REG_OFFSET_LR (30 * 8)
#define REG_OFFSET_SP (31 * 8)
#define REG_OFFSET_PC (32 * 8)

#define REG_FOREACH(OP_REG) \
  OP_REG(0)                            \
  OP_REG(1)                            \
  OP_REG(2)                            \
  OP_REG(3)                            \
  OP_REG(4)                            \
  OP_REG(5)                            \
  OP_REG(6)                            \
  OP_REG(7)                            \
  OP_REG(8)                            \
  OP_REG(9)                            \
  OP_REG(10)                           \
  OP_REG(11)                           \
  OP_REG(12)                           \
  OP_REG(13)                           \
  OP_REG(14)                           \
  OP_REG(15)                           \
  OP_REG(16)                           \
  OP_REG(17)                           \
  OP_REG(18)                           \
  OP_REG(19)                           \
  OP_REG(20)                           \
  OP_REG(21)                           \
  OP_REG(22)                           \
  OP_REG(23)                           \
  OP_REG(24)                           \
  OP_REG(25)                           \
  OP_REG(26)                           \
  OP_REG(27)                           \
  OP_REG(28)                           \
  OP_REG(29)                            

#define CHECK_OFFSET(reg, offset) static_assert(offsetof(zx_thread_state_general_regs_t, reg) == offset, "offset mismatch");

#define CHECK_OFFSET_R(reg) CHECK_OFFSET(r[reg], REG_OFFSET(reg))

REG_FOREACH(CHECK_OFFSET_R)
CHECK_OFFSET(sp, REG_OFFSET_SP)
CHECK_OFFSET(pc, REG_OFFSET_PC)
CHECK_OFFSET(lr, REG_OFFSET_LR)


#endif


// Trampoline to bridge from the assembly below to the static C++ crash
// callback.
__attribute__((noreturn))
static void StaticCrashHandler() {
  Fuzzer::StaticCrashSignalCallback();
  for (;;) {
    _Exit(1);
  }
}

// XSTR expands into a string literal containing the expansion of its arguments.
#define XSTR(...) STR(__VA_ARGS__)
#define STR(...) #__VA_ARGS__

// This macro expands into L, H, where L and H are bytes,
// representing the LEB128 encoding of X. 
// The first byte is bits [0, 7) of X, with a 1 in bit 7.
// The second byte is bits [7, 14) of X, with a 0 in bit 15. 
// It is only valid to call this macro with 0 <= X < 0x3FFF
#define ULEB128_2(X) (X & 0x7F) | 0x80, (X >> 7) & 0x7F

#define DW_CFA_def_cfa_expression 0x0f
#define DW_CFA_expression 0x10
#define DW_OP_breg7 0x77
#define DW_OP_deref 0x06

#if defined(__x86_64__)

#define cfi_cfa_deref_rsp(offset) ".cfi_escape " \
	"0x0f, " /* DW_CFA_def_cfa_expression */ \
	"0x04, "                      /* size */ \
	"0x77, "               /* DW_OP_breg7 */ \
       	XSTR(ULEB128_2(offset)) ", " /* offset*/ \
	"0x06  "               /* DW_OP_deref */ \
        "\n"

#define cfi_reg_from_rsp(regno, offset) ".cfi_escape " \
	"0x10, "               /* DW_CFA_expression */ \
	XSTR(regno) ", "         /* register number */ \
	"0x03, "                            /* size */ \
	"0x77, "                     /* DW_OP_breg7 */ \
	XSTR(ULEB128_2(offset))           /* offset */ \
	"\n"

#elif defined(__aarch64__)

#define cfi_cfa_deref_rsp(offset) ".cfi_escape " \
	"0x0f, " /* DW_CFA_def_cfa_expression */ \
	"0x04, "                      /* size */ \
	"0x8f, "              /* DW_OP_breg31 */ \
       	XSTR(ULEB128_2(offset)) ", " /* offset*/ \
	"0x06  "               /* DW_OP_deref */ \
        "\n"

#define cfi_reg_from_rsp(regno, offset) ".cfi_escape " \
	"0x10, "               /* DW_CFA_expression */ \
	XSTR(regno) ", "         /* register number */ \
	"0x03, "                            /* size */ \
	"0x8f, "                    /* DW_OP_breg31 */ \
	XSTR(ULEB128_2(offset))           /* offset */ \
	"\n"

#endif

#define cfi_reg(reg) cfi_reg_from_rsp(REG_DWARF_NUMBER(reg), REG_OFFSET(reg))

// Creates the trampoline with the necessary CFI information to unwind through
// to the crashing call stack:
//  * Defining the CFA so that it points to the stack pointer at the point
//    of crash.
//  * Storing all registers at the point of crash in the stack and refer to them
//    via CFI information (relative to the current stack pointer).
//  * Setting the return column so the unwinder knows how to continue unwinding.
//  * Calling StaticCrashHandler that will trigger the unwinder.
//
// The __attribute__((used)) is necessary because the function
// is never called; it's just a container around the assembly to allow it to
// use operands for compile-time computed constants.
__attribute__((used))
void MakeTrampoline() {
  __asm__(".cfi_endproc\n"
    ".pushsection .text.CrashTrampolineAsm\n"
    ".type CrashTrampolineAsm,STT_FUNC\n"
"CrashTrampolineAsm:\n"
    ".cfi_startproc simple\n"
    ".cfi_signal_frame\n"
#if defined(__x86_64__)
    cfi_cfa_deref_rsp(REG_OFFSET(rsp))
    REG_FOREACH(cfi_reg)
    ".cfi_return_column rip\n"
    "call %c[StaticCrashHandler]\n"
    "ud2\n"
#elif defined(__aarch64__)
    cfi_cfa_deref_rsp(REG_OFFSET_SP)
    cfi_reg_from_rsp(REG_DWARF_NUMBER_PC, REG_OFFSET_PC)
    cfi_reg_from_rsp(REG_DWARF_NUMBER_ELR, REG_OFFSET_PC)
    cfi_reg_from_rsp(REG_DWARF_NUMBER_LR, REG_OFFSET_LR)
    cfi_reg_from_rsp(REG_DWARF_NUMBER_SP, REG_OFFSET_SP)
    ".cfi_return_column 33\n"
    REG_FOREACH(cfi_reg)
    "bl %c[StaticCrashHandler]\n"
    "brk 1\n"
#else
#error "Unsupported architecture for fuzzing on Fuchsia"
#endif
    ".cfi_endproc\n"
    ".size CrashTrampolineAsm, . - CrashTrampolineAsm\n"
    ".popsection\n"
    ".cfi_startproc\n"
    : // No outputs
    : [StaticCrashHandler] "i" (StaticCrashHandler));
}

void CrashHandler(zx_handle_t *Event) {
  // This structure is used to ensure we close handles to objects we create in
  // this handler.
  struct ScopedHandle {
    ~ScopedHandle() { _zx_handle_close(Handle); }
    ScopedHandle() : Handle(ZX_HANDLE_INVALID) {}
    ScopedHandle(ScopedHandle &&Other)
        : Handle(std::exchange(Other.Handle, ZX_HANDLE_INVALID)) {}
    ScopedHandle(const ScopedHandle &Other) = delete;
    ScopedHandle &operator=(const ScopedHandle &) = delete;
    zx_handle_t Handle = ZX_HANDLE_INVALID;
  };

  // Create the exception channel.  We need to claim to be a "debugger" so the
  // kernel will allow us to modify and resume dying threads (see below). Once
  // the channel is set, we can signal the main thread to continue and wait
  // for the exception to arrive.
  ScopedHandle Channel;
  zx_handle_t Self = _zx_process_self();
  ExitOnErr(_zx_task_create_exception_channel(
                Self, ZX_EXCEPTION_CHANNEL_DEBUGGER, &Channel.Handle),
            "_zx_task_create_exception_channel");

  ExitOnErr(_zx_object_signal(*Event, 0, ZX_USER_SIGNAL_0),
            "_zx_object_signal");

  zx_koid_t crashed_tid = ZX_KOID_INVALID;
  std::vector<ScopedHandle> unhandled_exceptions;

  // This thread lives as long as the process in order to keep handling
  // crashes.  In practice, the first crashed thread to reach the end of the
  // StaticCrashHandler will end the process.
  while (true) {
    ExitOnErr(_zx_object_wait_one(Channel.Handle, ZX_CHANNEL_READABLE,
                                  ZX_TIME_INFINITE, nullptr),
              "_zx_object_wait_one");

    zx_exception_info_t ExceptionInfo;
    ScopedHandle Exception;
    ExitOnErr(_zx_channel_read(Channel.Handle, 0, &ExceptionInfo,
                               &Exception.Handle, sizeof(ExceptionInfo), 1,
                               nullptr, nullptr),
              "_zx_channel_read");

    // Ignore informational synthetic exceptions.
    if (ZX_EXCP_THREAD_STARTING == ExceptionInfo.type ||
        ZX_EXCP_THREAD_EXITING == ExceptionInfo.type ||
        ZX_EXCP_PROCESS_STARTING == ExceptionInfo.type) {
      continue;
    }

    // At this point, we want to get the state of the crashing thread, but
    // libFuzzer and the sanitizers assume this will happen from that same
    // thread via a POSIX signal handler. "Resurrecting" the thread in the
    // middle of the appropriate callback is as simple as forcibly setting the
    // instruction pointer/program counter, provided we NEVER EVER return from
    // that function (since otherwise our stack will not be valid).
    ScopedHandle Thread;
    ExitOnErr(_zx_exception_get_thread(Exception.Handle, &Thread.Handle),
              "_zx_exception_get_thread");

    zx_thread_state_general_regs_t GeneralRegisters;
    ExitOnErr(_zx_thread_read_state(Thread.Handle, ZX_THREAD_STATE_GENERAL_REGS,
                                    &GeneralRegisters,
                                    sizeof(GeneralRegisters)),
              "_zx_thread_read_state");

    if (crashed_tid != ZX_KOID_INVALID) {
      // If we reach this point it means that we received more than
      // one exception. This new exception could either be from the
      // same thread as the first exception or from another thread.
      Printf("libFuzzer: An exception occurred while handling a previous "
             "crash.\n");
      if (crashed_tid == ExceptionInfo.tid) {
        // Exception came from the same thread. This means that the exception
        // handling code crashed. This is bad. Exiting here at least
        // will generate a crashing artifact.
        exit(1);
      } else {
        // We received a crash from a different thread. Leave it suspended and
        // wait for the next exception.
        unhandled_exceptions.push_back(std::move(Exception));
        continue;
      }
    }

    crashed_tid = ExceptionInfo.tid;
    Printf("LF Version 1");

    // To unwind properly, we need to push the crashing thread's register state
    // onto the stack and jump into a trampoline with CFI instructions on how
    // to restore it.
#if defined(__x86_64__)
    uintptr_t StackPtr =
        reinterpret_cast<uintptr_t>(&CrashStack[kCrashStackSize]) - CFAOffset;
    __unsanitized_memcpy(reinterpret_cast<void *>(StackPtr), &GeneralRegisters,
                         sizeof(GeneralRegisters));
    GeneralRegisters.rsp = StackPtr;
    GeneralRegisters.rip = reinterpret_cast<zx_vaddr_t>(CrashTrampolineAsm);

#elif defined(__aarch64__)
    uintptr_t StackPtr =
        reinterpret_cast<uintptr_t>(&CrashStack[kCrashStackSize]) - CFAOffset;
    __unsanitized_memcpy(reinterpret_cast<void *>(StackPtr), &GeneralRegisters,
                         sizeof(GeneralRegisters));
    GeneralRegisters.sp = StackPtr;
    GeneralRegisters.pc = reinterpret_cast<zx_vaddr_t>(CrashTrampolineAsm);

#else
#error "Unsupported architecture for fuzzing on Fuchsia"
#endif

    // Now force the crashing thread's state.
    ExitOnErr(
        _zx_thread_write_state(Thread.Handle, ZX_THREAD_STATE_GENERAL_REGS,
                               &GeneralRegisters, sizeof(GeneralRegisters)),
        "_zx_thread_write_state");

    // Set the exception to HANDLED so it resumes the thread on close.
    uint32_t ExceptionState = ZX_EXCEPTION_STATE_HANDLED;
    ExitOnErr(_zx_object_set_property(Exception.Handle, ZX_PROP_EXCEPTION_STATE,
                                      &ExceptionState, sizeof(ExceptionState)),
              "zx_object_set_property");
  }
}

} // namespace

// Platform specific functions.
void SetSignalHandler(const FuzzingOptions &Options) {
  // Make sure information from libFuzzer and the sanitizers are easy to
  // reassemble. `__sanitizer_log_write` has the added benefit of ensuring the
  // DSO map is always available for the symbolizer.
  // A uint64_t fits in 20 chars, so 64 is plenty.
  char Buf[64];
  memset(Buf, 0, sizeof(Buf));
  snprintf(Buf, sizeof(Buf), "==%lu== INFO: libFuzzer starting.\n", GetPid());
  if (EF->__sanitizer_log_write)
    __sanitizer_log_write(Buf, sizeof(Buf));
  Printf("%s", Buf);

  // Set up alarm handler if needed.
  if (Options.HandleAlrm && Options.UnitTimeoutSec > 0) {
    std::thread T(AlarmHandler, Options.UnitTimeoutSec / 2 + 1);
    T.detach();
  }

  // Options.HandleInt and Options.HandleTerm are not supported on Fuchsia

  // Early exit if no crash handler needed.
  if (!Options.HandleSegv && !Options.HandleBus && !Options.HandleIll &&
      !Options.HandleFpe && !Options.HandleAbrt)
    return;

  // Set up the crash handler and wait until it is ready before proceeding.
  zx_handle_t Event;
  ExitOnErr(_zx_event_create(0, &Event), "_zx_event_create");

  std::thread T(CrashHandler, &Event);
  zx_status_t Status =
      _zx_object_wait_one(Event, ZX_USER_SIGNAL_0, ZX_TIME_INFINITE, nullptr);
  _zx_handle_close(Event);
  ExitOnErr(Status, "_zx_object_wait_one");

  T.detach();
}

void SleepSeconds(int Seconds) {
  _zx_nanosleep(_zx_deadline_after(ZX_SEC(Seconds)));
}

unsigned long GetPid() {
  zx_status_t rc;
  zx_info_handle_basic_t Info;
  if ((rc = _zx_object_get_info(_zx_process_self(), ZX_INFO_HANDLE_BASIC, &Info,
                                sizeof(Info), NULL, NULL)) != ZX_OK) {
    Printf("libFuzzer: unable to get info about self: %s\n",
           _zx_status_get_string(rc));
    exit(1);
  }
  return Info.koid;
}

size_t GetPeakRSSMb() {
  zx_status_t rc;
  zx_info_task_stats_t Info;
  if ((rc = _zx_object_get_info(_zx_process_self(), ZX_INFO_TASK_STATS, &Info,
                                sizeof(Info), NULL, NULL)) != ZX_OK) {
    Printf("libFuzzer: unable to get info about self: %s\n",
           _zx_status_get_string(rc));
    exit(1);
  }
  return (Info.mem_private_bytes + Info.mem_shared_bytes) >> 20;
}

template <typename Fn>
class RunOnDestruction {
 public:
  explicit RunOnDestruction(Fn fn) : fn_(fn) {}
  ~RunOnDestruction() { fn_(); }

 private:
  Fn fn_;
};

template <typename Fn>
RunOnDestruction<Fn> at_scope_exit(Fn fn) {
  return RunOnDestruction<Fn>(fn);
}

static fdio_spawn_action_t clone_fd_action(int localFd, int targetFd) {
  return {
      .action = FDIO_SPAWN_ACTION_CLONE_FD,
      .fd =
          {
              .local_fd = localFd,
              .target_fd = targetFd,
          },
  };
}

int ExecuteCommand(const Command &Cmd) {
  zx_status_t rc;

  // Convert arguments to C array
  auto Args = Cmd.getArguments();
  size_t Argc = Args.size();
  assert(Argc != 0);
  std::unique_ptr<const char *[]> Argv(new const char *[Argc + 1]);
  for (size_t i = 0; i < Argc; ++i)
    Argv[i] = Args[i].c_str();
  Argv[Argc] = nullptr;

  // Determine output.  On Fuchsia, the fuzzer is typically run as a component
  // that lacks a mutable working directory. Fortunately, when this is the case
  // a mutable output directory must be specified using "-artifact_prefix=...",
  // so write the log file(s) there.
  // However, we don't want to apply this logic for absolute paths.
  int FdOut = STDOUT_FILENO;
  bool discardStdout = false;
  bool discardStderr = false;

  if (Cmd.hasOutputFile()) {
    std::string Path = Cmd.getOutputFile();
    if (Path == getDevNull()) {
      // On Fuchsia, there's no "/dev/null" like-file, so we
      // just don't copy the FDs into the spawned process.
      discardStdout = true;
    } else {
      bool IsAbsolutePath = Path.length() > 1 && Path[0] == '/';
      if (!IsAbsolutePath && Cmd.hasFlag("artifact_prefix"))
        Path = Cmd.getFlagValue("artifact_prefix") + "/" + Path;

      FdOut = open(Path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0);
      if (FdOut == -1) {
        Printf("libFuzzer: failed to open %s: %s\n", Path.c_str(),
               strerror(errno));
        return ZX_ERR_IO;
      }
    }
  }
  auto CloseFdOut = at_scope_exit([FdOut]() {
    if (FdOut != STDOUT_FILENO)
      close(FdOut);
  });

  // Determine stderr
  int FdErr = STDERR_FILENO;
  if (Cmd.isOutAndErrCombined()) {
    FdErr = FdOut;
    if (discardStdout)
      discardStderr = true;
  }

  // Clone the file descriptors into the new process
  std::vector<fdio_spawn_action_t> SpawnActions;
  SpawnActions.push_back(clone_fd_action(STDIN_FILENO, STDIN_FILENO));

  if (!discardStdout)
    SpawnActions.push_back(clone_fd_action(FdOut, STDOUT_FILENO));
  if (!discardStderr)
    SpawnActions.push_back(clone_fd_action(FdErr, STDERR_FILENO));

  // Start the process.
  char ErrorMsg[FDIO_SPAWN_ERR_MSG_MAX_LENGTH];
  zx_handle_t ProcessHandle = ZX_HANDLE_INVALID;
  rc = fdio_spawn_etc(ZX_HANDLE_INVALID,
                      FDIO_SPAWN_CLONE_ALL & (~FDIO_SPAWN_CLONE_STDIO), Argv[0],
                      Argv.get(), nullptr, SpawnActions.size(),
                      SpawnActions.data(), &ProcessHandle, ErrorMsg);

  if (rc != ZX_OK) {
    Printf("libFuzzer: failed to launch '%s': %s, %s\n", Argv[0], ErrorMsg,
           _zx_status_get_string(rc));
    return rc;
  }
  auto CloseHandle = at_scope_exit([&]() { _zx_handle_close(ProcessHandle); });

  // Now join the process and return the exit status.
  if ((rc = _zx_object_wait_one(ProcessHandle, ZX_PROCESS_TERMINATED,
                                ZX_TIME_INFINITE, nullptr)) != ZX_OK) {
    Printf("libFuzzer: failed to join '%s': %s\n", Argv[0],
           _zx_status_get_string(rc));
    return rc;
  }

  zx_info_process_t Info;
  if ((rc = _zx_object_get_info(ProcessHandle, ZX_INFO_PROCESS, &Info,
                                sizeof(Info), nullptr, nullptr)) != ZX_OK) {
    Printf("libFuzzer: unable to get return code from '%s': %s\n", Argv[0],
           _zx_status_get_string(rc));
    return rc;
  }

  return Info.return_code;
}

bool ExecuteCommand(const Command &BaseCmd, std::string *CmdOutput) {
  auto LogFilePath = TempPath("SimPopenOut", ".txt");
  Command Cmd(BaseCmd);
  Cmd.setOutputFile(LogFilePath);
  int Ret = ExecuteCommand(Cmd);
  *CmdOutput = FileToString(LogFilePath);
  RemoveFile(LogFilePath);
  return Ret == 0;
}

const void *SearchMemory(const void *Data, size_t DataLen, const void *Patt,
                         size_t PattLen) {
  return memmem(Data, DataLen, Patt, PattLen);
}

// In fuchsia, accessing /dev/null is not supported. There's nothing
// similar to a file that discards everything that is written to it.
// The way of doing something similar in fuchsia is by using
// fdio_null_create and binding that to a file descriptor.
void DiscardOutput(int Fd) {
  fdio_t *fdio_null = fdio_null_create();
  if (fdio_null == nullptr) return;
  int nullfd = fdio_bind_to_fd(fdio_null, -1, 0);
  if (nullfd < 0) return;
  dup2(nullfd, Fd);
}

} // namespace fuzzer

#endif // LIBFUZZER_FUCHSIA
