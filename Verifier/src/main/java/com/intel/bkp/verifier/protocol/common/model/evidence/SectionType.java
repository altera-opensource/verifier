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

package com.intel.bkp.verifier.protocol.common.model.evidence;

import com.intel.bkp.verifier.exceptions.SectionTypeException;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;
import java.util.stream.Stream;

import static com.intel.bkp.utils.HexConverter.toHex;

@Getter
@AllArgsConstructor
public enum SectionType {
    RESERVED(0, 0),
    DEVICE_STATE(1, 0x82),
    IO(2, 0x01),
    CORE(3, 0x01),
    HPIO(4, 0x01),
    HPS(5, 0x01),
    PR(6, 0x01),
    LAYER_0_FW_ROM_EXT(10, 0), // FM/DM, untyped
    LAYER_1_FW_CMF(11, 0), // untyped
    LAYER_2_BASE_DESIGN(12, 0); // FM/DM, untyped

    public static final int MIN_PR_INDEX = 0x40;
    public static final int MAX_PR_INDEX = 0x5F;

    private final int value;
    private final int type;

    static final String UNSUPPORTED_SECTION_TYPE = "Unsupported SectionType. Value: %d (0x%s).";
    static final String FAILED_TO_DETERMINE_SECTION_TYPE = "Failed to determine section type from RIM file.";
    static final String TYPE_IDENTIFIER_MUST_BE_BYTE_VALUE = "Type identifier must be byte value.";
    static final String LAYER_MUST_BE_INTEGER_VALUE = "Layer must be integer value.";
    static final String LAYER_CAN_ONLY_HAVE_VALUES = "Layer can only have values 0, 1 or 2.";
    static final String UNSUPPORTED_SPDM_SECTION =
        "Unsupported SectionType. SPDM Index: %d (0x%s), SPDM Type: %d (0x%s)";

    public static SectionType from(byte value) {
        return Arrays.stream(values())
            .filter(type -> type.getValue() == toInt(value))
            .findFirst()
            .orElseThrow(
                () -> new SectionTypeException(String.format(UNSUPPORTED_SECTION_TYPE, value, toHex(value)))
            );
    }

    public static SectionType fromSpdmParameters(byte spdmIndex, byte spdmType) {
        if (isSpdmSection(spdmIndex, spdmType)) {
            return from(spdmIndex);
        } else if (isSpdmPrSection(spdmIndex, spdmType)) {
            return PR;
        } else {
            throw new SectionTypeException(
                UNSUPPORTED_SPDM_SECTION.formatted(spdmIndex, toHex(spdmIndex), spdmType, toHex(spdmType)));
        }
    }

    private static boolean isSpdmSection(byte spdmIndex, byte spdmType) {
        return Stream.of(DEVICE_STATE, IO, CORE, HPIO, HPS)
            .anyMatch(v -> v.getValue() == toInt(spdmIndex) && v.getType() == toInt(spdmType));
    }

    private static boolean isSpdmPrSection(byte spdmIndex, byte spdmType) {
        return toInt(spdmIndex) >= MIN_PR_INDEX
            && toInt(spdmIndex) <= MAX_PR_INDEX
            && toInt(spdmType) == PR.getType();
    }

    private static int toInt(byte byteVal) {
        return byteVal & 0xFF;
    }
}
