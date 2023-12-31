/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

TEST_BEGIN(BTRr16i8, 1)
TEST_IGNORE_FLAGS(OF SF ZF AF PF)
TEST_INPUTS(
    0,
    1)

    btr ARG1_16, 1
TEST_END

TEST_BEGIN(BTRr16r16, 2)
TEST_IGNORE_FLAGS(OF SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFFFF, 16,
    0xFFFF, 15,
    0xFFFE, 16)

    btr ARG1_16, ARG2_16
TEST_END

TEST_BEGIN_64(BTRm16r16, 1)
TEST_IGNORE_FLAGS(OF SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    15,
    16,
    31,
    32,
    63)

    mov DWORD PTR [rsp - 8], 0xFF00FF00
    mov DWORD PTR [rsp - 4], 0xFF00FF00
    btr WORD PTR [rsp - 8], ARG1_16
TEST_END_64

TEST_BEGIN(BTRr32i8, 1)
TEST_IGNORE_FLAGS(OF SF ZF AF PF)
TEST_INPUTS(
    0,
    1)

    btr ARG1_32, 1
TEST_END

TEST_BEGIN_64(BTRm32r32, 1)
TEST_IGNORE_FLAGS(OF SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    15,
    16,
    31,
    32,
    63)

    mov DWORD PTR [rsp - 8], 0xFF00FF00
    mov DWORD PTR [rsp - 4], 0xFF00FF00
    btr DWORD PTR [rsp - 8], ARG1_32
TEST_END_64

TEST_BEGIN(BTRr32r32, 2)
TEST_IGNORE_FLAGS(OF SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFFFF, 16,
    0xFFFF, 15,
    0xFFFE, 16,
    0xFFFFFFFF, 32,
    0xFFFFFFFF, 31,
    0xFFFFFFFE, 32)

    btr ARG1_32, ARG2_32
TEST_END

TEST_BEGIN_64(BTRr32i8_64, 1)
TEST_IGNORE_FLAGS(OF SF ZF AF PF)
TEST_INPUTS(
    0,
    1)

    btr ARG1_64, 1
TEST_END_64

TEST_BEGIN_64(BTRr64r64_64, 2)
TEST_IGNORE_FLAGS(OF SF ZF AF PF)
TEST_INPUTS(
    0, 0,
    1, 0,
    0xFFFF, 16,
    0xFFFF, 15,
    0xFFFE, 16,
    0xFFFFFFFF, 32,
    0xFFFFFFFF, 31,
    0xFFFFFFFE, 32,
    0xFFFFFFFFFFFFFFFE, 64,
    0xFFFFFFFFFFFFFFFF, 63,
    0xFFFFFFFFFFFFFFFE, 64)

    btr ARG1_64, ARG2_64
TEST_END_64

TEST_BEGIN_64(BTRm64r64_64, 1)
TEST_IGNORE_FLAGS(OF SF ZF AF PF)
TEST_INPUTS(
    0,
    1,
    15,
    16,
    31,
    32,
    63)

    mov DWORD PTR [rsp - 8], 0xFF00FF00
    mov DWORD PTR [rsp - 4], 0xFF00FF00
    btr QWORD PTR [rsp - 8], ARG1_64
TEST_END_64
