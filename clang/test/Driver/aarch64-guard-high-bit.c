// RUN: %clang --target=aarch64-unknown-fuchsia -mguard-high-bit=47 -### -c %s 2>&1 | FileCheck %s --check-prefix=BIT47
// RUN: %clang --target=aarch64-unknown-fuchsia -mguard-high-bit=0 -### -c %s 2>&1 | FileCheck %s --check-prefix=BIT0
// RUN: %clang --target=aarch64-unknown-fuchsia -mguard-high-bit=47 -mguard-high-bit=none -### -c %s 2>&1 | FileCheck %s --check-prefix=NONE
// RUN: not %clang --target=aarch64-unknown-fuchsia -mguard-high-bit=64 -### -c %s 2>&1 | FileCheck %s --check-prefix=ERR-VAL
// RUN: not %clang --target=x86_64-unknown-fuchsia -mguard-high-bit=47 -### -c %s 2>&1 | FileCheck %s --check-prefix=ERR-TARGET

// BIT47: "-mguard-high-bit=47"
// BIT0: "-mguard-high-bit=0"
// NONE-NOT: "-mguard-high-bit="
// ERR-VAL: error: unsupported argument '64' to option '-mguard-high-bit='
// ERR-TARGET: error: unsupported option '-mguard-high-bit=' for target 'x86_64-unknown-fuchsia'
