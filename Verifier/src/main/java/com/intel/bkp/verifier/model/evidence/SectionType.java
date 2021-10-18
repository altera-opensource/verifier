/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.model.evidence;

import com.intel.bkp.verifier.exceptions.SectionTypeException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

import java.util.Arrays;
import java.util.Optional;

@Getter
@AllArgsConstructor
public enum SectionType {
    RESERVED(0),
    DEVICE_STATE(1),
    IO(2),
    CORE(3),
    HPIO(4),
    HPS(5),
    PR(6),
    LAYER_0_FW_ROM_EXT(10), // FM/DM, untyped
    LAYER_1_FW_CMF(11), // untyped
    LAYER_2_BASE_DESIGN(12); // FM/DM, untyped

    private final int value;

    static final String UNSUPPORTED_SECTION_TYPE = "Unsupported SectionType value (%d).";
    static final String FAILED_TO_DETERMINE_SECTION_TYPE = "Failed to determine section type from RIM file.";
    static final String TYPE_IDENTIFIER_MUST_BE_BYTE_VALUE = "Type identifier must be byte value.";
    static final String LAYER_MUST_BE_INTEGER_VALUE = "Layer must be integer value.";
    static final String LAYER_CAN_ONLY_HAVE_VALUES = "Layer can only have values 0, 1 or 2.";

    public static SectionType from(byte b) {
        return Arrays.stream(values())
            .filter(type -> type.getValue() == b)
            .findFirst()
            .orElseThrow(
                () -> new SectionTypeException(String.format(UNSUPPORTED_SECTION_TYPE, b))
            );
    }

    public static SectionType from(BaseEvidenceBlock block) {
        return Optional.ofNullable(block.getType())
            .map(SectionType::determineSectionTypeFromType)
            .orElseGet(() -> fromLayer(block));
    }

    public static SectionType fromTypeLayer(String type, Integer layer) {
        return Optional.ofNullable(type)
            .map(SectionType::determineSectionTypeFromType)
            .orElseGet(() -> determineSectionTypeFromLayer(layer));
    }

    private static SectionType fromLayer(BaseEvidenceBlock block) {
        return Optional.ofNullable(block.getLayer())
            .map(SectionType::determineSectionTypeFromLayer)
            .orElseThrow(() -> new SectionTypeException(FAILED_TO_DETERMINE_SECTION_TYPE));
    }

    private static SectionType determineSectionTypeFromType(@NonNull String type) {
        final String[] typeIntegers = type.split("[.]");

        try {
            final byte typeByte = Byte.parseByte(typeIntegers[typeIntegers.length - 1]);
            return SectionType.from(typeByte);
        } catch (NumberFormatException e) {
            throw new SectionTypeException(TYPE_IDENTIFIER_MUST_BE_BYTE_VALUE, e);
        }
    }

    private static SectionType determineSectionTypeFromLayer(@NonNull String layer) {
        try {
            return SectionType.determineSectionTypeFromLayer(Integer.parseInt(layer));
        } catch (NumberFormatException e) {
            throw new SectionTypeException(LAYER_MUST_BE_INTEGER_VALUE, e);
        }
    }

    private static SectionType determineSectionTypeFromLayer(int layer) {
        if (layer == 0) {
            return LAYER_0_FW_ROM_EXT;
        } else if (layer == 1) {
            return LAYER_1_FW_CMF;
        } else if (layer == 2) {
            return LAYER_2_BASE_DESIGN;
        }

        throw new SectionTypeException(LAYER_CAN_ONLY_HAVE_VALUES);
    }
}
