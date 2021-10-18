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

package com.intel.bkp.ext.core.manufacturing.model;

import com.intel.bkp.ext.core.exceptions.UnknownFamilyIdException;
import com.intel.bkp.ext.core.interfaces.IEfuseBlockData;
import com.intel.bkp.ext.core.manufacturing.AgilexEfuseBlockBuilder;
import com.intel.bkp.ext.core.manufacturing.EasicN5xEfuseBlockBuilder;
import com.intel.bkp.ext.core.manufacturing.enumeration.DataType;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;

@AllArgsConstructor
@Getter
public enum AttFamily {
    AGILEX(DataType.ARIES_FM, "agilex", (byte) 0x34, 101, new AgilexEfuseBlockBuilder()),
    EASIC_N5X(DataType.ARIES_DM, "easic_n5x", (byte) 0x35, 102, new EasicN5xEfuseBlockBuilder());

    private final DataType dataType;
    private final String familyName;
    private final byte familyId;
    private final int issuerId; // Must match value associated with given family in CA Service
    private final IEfuseBlockData efuseBlockData;

    public static AttFamily from(byte familyId) {
        return Arrays.stream(values())
            .filter(family -> family.familyId == familyId)
            .findFirst()
            .orElseThrow(UnknownFamilyIdException::new);
    }
}
