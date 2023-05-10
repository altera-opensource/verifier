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

package com.intel.bkp.fpgacerts.model;

import com.intel.bkp.fpgacerts.exceptions.UnknownFamilyIdException;
import lombok.Getter;

import java.util.Arrays;
import java.util.Optional;

import static java.lang.Byte.toUnsignedInt;

@Getter
public enum FamilyId {
    S10((byte) 0x32),
    AGILEX((byte) 0x34),
    EASIC_N5X((byte) 0x35),
    MEV((byte) 0x01),
    LKV((byte) 0x02),
    CNV((byte) 0x03);

    private final byte value;
    private final Integer integerValue;

    private FamilyId(byte value) {
        this.value = value;
        this.integerValue = toUnsignedInt(value);
    }

    public static FamilyId from(byte id) {
        return from(toUnsignedInt(id));
    }

    public static FamilyId from(Integer id) {
        return find(id).orElseThrow(UnknownFamilyIdException::new);
    }

    public static Optional<FamilyId> find(Integer id) {
        return Arrays.stream(values())
            .filter(familyId -> familyId.integerValue.equals(id))
            .findFirst();
    }

    public static Integer s10Workaround(Integer familyId) {
        return familyId == 50 ? null : familyId;
    }
}
