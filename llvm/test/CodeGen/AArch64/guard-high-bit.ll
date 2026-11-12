; RUN: llc -mtriple=aarch64-unknown-fuchsia -aarch64-guard-high-bit=47 -verify-machineinstrs < %s | FileCheck %s --check-prefix=BIT47
; RUN: llc -mtriple=aarch64-unknown-fuchsia -aarch64-guard-high-bit=12 -verify-machineinstrs < %s | FileCheck %s --check-prefix=BIT12
; RUN: llc -mtriple=aarch64-unknown-fuchsia -verify-machineinstrs < %s | FileCheck %s --check-prefix=DEFAULT

define i64 @indirect_call(ptr %fn, i64 %x) {
; BIT47-LABEL: indirect_call:
; BIT47:       tbnz x8, #47, .Ltmp
; BIT47-NEXT:  brk #0x1
; BIT47-NEXT: .Ltmp
; BIT47-NEXT:  blr x8
; BIT12-LABEL: indirect_call:
; BIT12:       tbnz w8, #12, .Ltmp
; BIT12-NEXT:  brk #0x1
; BIT12-NEXT: .Ltmp
; BIT12-NEXT:  blr x8
; DEFAULT-LABEL: indirect_call:
; DEFAULT-NOT: tbnz
; DEFAULT:     blr x8
  %res = call i64 %fn(i64 %x)
  %inc = add i64 %res, 1
  ret i64 %inc
}

define i64 @indirect_tail_call(ptr %fn, i64 %x) {
; BIT47-LABEL: indirect_tail_call:
; BIT47:       tbnz x{{[0-9]+}}, #47, .Ltmp
; BIT47-NEXT:  brk #0x1
; BIT47-NEXT: .Ltmp
; BIT47-NEXT:  br x{{[0-9]+}}
; DEFAULT-LABEL: indirect_tail_call:
; DEFAULT-NOT: tbnz
; DEFAULT:     br x{{[0-9]+}}
  %res = tail call i64 %fn(i64 %x)
  ret i64 %res
}

define i64 @fn_attr_override_none(ptr %fn, i64 %x) "guard-high-bit"="none" {
; BIT47-LABEL: fn_attr_override_none:
; BIT47-NOT:   tbnz
; BIT47:       blr x8
  %res = call i64 %fn(i64 %x)
  %inc = add i64 %res, 1
  ret i64 %inc
}

define i64 @fn_attr_explicit_46(ptr %fn, i64 %x) "guard-high-bit"="46" {
; DEFAULT-LABEL: fn_attr_explicit_46:
; DEFAULT:       tbnz x8, #46, .Ltmp
; DEFAULT-NEXT:  brk #0x1
; DEFAULT-NEXT: .Ltmp
; DEFAULT-NEXT:  blr x8
  %res = call i64 %fn(i64 %x)
  %inc = add i64 %res, 1
  ret i64 %inc
}
