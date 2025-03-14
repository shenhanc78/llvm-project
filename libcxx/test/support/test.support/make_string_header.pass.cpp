//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// UNSUPPORTED: c++03
// UNSUPPORTED: no-localization

// "support/make_string.h"

#include "make_string.h"
#include <cassert>

#include "test_macros.h"

int main(int, char**) {
  // clang-format off
  assert(MAKE_STRING(char,
         " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN"
             "OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")
    ==   " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN"
             "OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~");

#ifndef TEST_HAS_NO_WIDE_CHARACTERS
  assert(MAKE_STRING(wchar_t,
         " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN"
             "OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")
    ==  L" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN"
             "OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~");
#endif
#if _LIBCPP_HAS_CHAR8_T
  assert(MAKE_STRING(char8_t,
         " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN"
             "OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")
    == u8" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN"
             "OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~");
#endif
  assert(MAKE_STRING(char16_t,
         " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN"
             "OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")
    ==  u" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN"
             "OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~");

  assert(MAKE_STRING(char32_t,
         " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN"
             "OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")
    ==  U" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN"
             "OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~");

  // clang-format on
  return 0;
}
