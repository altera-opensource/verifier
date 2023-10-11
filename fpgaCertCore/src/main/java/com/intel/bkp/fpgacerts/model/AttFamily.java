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
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Locale;

@AllArgsConstructor
@Getter
public enum AttFamily implements IFamily {
    AGILEX(Family.AGILEX),
    EASIC_N5X(Family.EASIC_N5X),
    AGILEX_B(Family.AGILEX_B);

    private final Family family;

    public static AttFamily from(byte familyId) {
        return Arrays.stream(values())
            .filter(family -> family.getFamilyId() == familyId)
            .findFirst()
            .orElseThrow(UnknownFamilyIdException::new);
    }

    public static AttFamily from(String familyName) {
        return Arrays.stream(values())
            .filter(family -> family.getFamilyName().equals(familyName)
                || StringUtils.capitalize(family.getFamilyName()).equals(familyName))
            .findFirst()
            .orElseThrow(UnknownFamilyIdException::new);
    }

    @Override
    public String getFamilyName() {
        return family.getFamilyName().toLowerCase(Locale.ROOT);
    }

    @Override
    public byte getFamilyId() {
        return family.getFamilyId();
    }
}
