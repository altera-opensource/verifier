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

package com.intel.bkp.core.manufacturing.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.EnumSet;
import java.util.Locale;

import static com.intel.bkp.utils.HexConverter.toHex;

/**
 * The PufType enumeration.
 */
@RequiredArgsConstructor
@Getter
public enum PufType {
    IID("UDS_IID"),
    INTEL("UDS_INTEL"),
    EFUSE("UDS_EFUSE"),
    IIDUSER("USER_IID"),
    INTEL_USER("USER_INTEL");

    private final String alternativeName;

    public static PufType fromOrdinal(Integer ordinal) {
        return EnumSet.allOf(PufType.class).stream()
            .filter(entitlementType -> entitlementType.ordinal() == ordinal)
            .findFirst()
            .orElseThrow(IllegalArgumentException::new);
    }

    public static String getPufTypeHex(PufType pufType) {
        return toHex(ByteBuffer.allocate(Integer.BYTES)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(pufType.ordinal())
            .array()
        ).toUpperCase(Locale.ROOT);
    }

    public static String getPufTypeHex(String pufTypeName) {
        return getPufTypeHex(PufType.valueOf(pufTypeName));
    }
}
