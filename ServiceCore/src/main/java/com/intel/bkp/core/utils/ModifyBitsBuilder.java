/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2023 Intel Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * **************************************************************************
 *
 */

package com.intel.bkp.core.utils;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class ModifyBitsBuilder {

    private static final int ALL_BITS_SET = 0xFFFFFFFF;
    private static final int NONE_BITS_SET = 0x00000000;

    private int number;

    public static ModifyBitsBuilder fromAll() {
        return new ModifyBitsBuilder(ALL_BITS_SET);
    }

    public static ModifyBitsBuilder fromNone() {
        return new ModifyBitsBuilder(NONE_BITS_SET);
    }

    public ModifyBitsBuilder set(int position) {
        modify(position, 1);
        return this;
    }

    public ModifyBitsBuilder unset(int position) {
        modify(position, 0);
        return this;
    }

    public int build() {
        return number;
    }

    private void modify(int position, int value) {
        int mask = 1 << position;
        number = (number & ~mask) | ((value << position) & mask);
    }

    public String toString() {
        return String.format("%32s", Integer.toBinaryString(number)).replace(' ', '0');
    }
}
