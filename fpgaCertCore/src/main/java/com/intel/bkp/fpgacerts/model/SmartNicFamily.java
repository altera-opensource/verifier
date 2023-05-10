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
import com.intel.bkp.fpgacerts.interfaces.IFamily;
import com.intel.bkp.utils.FirstIntegerByteParser;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Locale;

@AllArgsConstructor
@Getter
public enum SmartNicFamily implements IFamily {
    MEV("IPU ES2000", (byte) 0x01),
    LKV("Enet Controller E610", (byte) 0x02),
    CNV("Enet Controller E830", (byte) 0x03);

    private final String familyName;
    private final byte familyId;

    public static SmartNicFamily from(byte[] data) {
        return FirstIntegerByteParser.from(data, values(), SmartNicFamily::getFamilyId);
    }

    public static SmartNicFamily from(byte familyId) {
        return Arrays.stream(values())
            .filter(family -> family.familyId == familyId)
            .findFirst()
            .orElseThrow(UnknownFamilyIdException::new);
    }

    public static SmartNicFamily from(String familyName) {
        return Arrays.stream(values())
            .filter(family -> family.familyName.equals(familyName)
                || StringUtils.capitalize(family.familyName.toLowerCase(Locale.ROOT)).equals(familyName))
            .findFirst()
            .orElseThrow(IllegalArgumentException::new);
    }
}
