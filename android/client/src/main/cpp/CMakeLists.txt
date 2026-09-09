cmake_minimum_required(VERSION 3.22.1)
project(millyguard)

# A small library, deliberately native. The checks it performs are trivial to
# read and delete when written in Kotlin, because Kotlin decompiles cleanly;
# native ARM does not, and the self-attach below cannot be expressed in the JVM
# at all. Optimised and with symbols stripped so the strings inside are not a
# map of what it looks for.
add_library(millyguard SHARED millyguard.c)

# The hardening set for a library that ships to handsets.
#
# -fno-stack-protector used to sit here, and it is hard to read that as anything
# but a mistake: this file parses attacker-influenced text into fixed C buffers
# — /proc/self/status, /proc/self/maps, system properties — which is exactly the
# shape of code guard pages were invented for, and it was compiled with the
# guard turned off. -fstack-protector-strong covers every function with an array
# or an address-taken local, which is all of them here, and costs a few
# instructions on functions called a handful of times per session.
#
# _FORTIFY_SOURCE=2 turns the string and memory calls into their checked bionic
# variants where the destination size is known at compile time. It is undefined
# first because the NDK toolchain already sets a level of its own in optimised
# builds, and redefining a macro that is already defined is a warning; -O2 above
# is what makes any of it take effect, since fortification needs the optimiser
# to know the sizes.
#
# -fPIC is not listed: CMake compiles SHARED library sources position
# independent already, and it is the only thing the Android linker will load.
# -fPIE is for executables and would be wrong on a .so, so it is not here either.
target_compile_options(millyguard PRIVATE
    -O2
    -fvisibility=hidden
    -fstack-protector-strong
    -U_FORTIFY_SOURCE
    -D_FORTIFY_SOURCE=2)

# 16 KB page alignment. Android is moving to 16 KB memory pages and a LOAD
# segment aligned only to 4 KB is rejected on those devices; a real Galaxy S23
# flagged exactly this. max-page-size pushes the segment alignment to 16 KB.
#
# relro and now together are full RELRO: the GOT is resolved at load and the
# whole of it made read-only, so an arbitrary-write primitive cannot reach a
# function pointer through it. noexecstack marks the stack non-executable. Both
# of those, like PIC above, are already the default in the NDK's lld — they are
# written out anyway because a defaulted mitigation is one a toolchain upgrade
# can silently withdraw, and this is a cheap place to say what the library
# requires rather than what it happens to get.
target_link_options(millyguard PRIVATE
    -Wl,--exclude-libs,ALL
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    -Wl,-z,max-page-size=16384)

find_library(log-lib log)
target_link_libraries(millyguard ${log-lib})
