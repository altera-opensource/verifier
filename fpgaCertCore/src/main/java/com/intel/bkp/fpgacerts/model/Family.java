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
import lombok.Getter;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.model.FamilyType.FPGA;
import static com.intel.bkp.fpgacerts.model.FamilyType.NIC;
import static com.intel.bkp.utils.HexConverter.fromHexSingle;
import static com.intel.bkp.utils.HexConverter.toHex;
import static java.lang.Byte.toUnsignedInt;

@Getter
public enum Family implements IFamily {
    S10((byte) 0x32, "Stratix 10", FPGA),
    AGILEX((byte) 0x34, "Agilex", FPGA),
    EASIC_N5X((byte) 0x35, "Easic_n5x", FPGA),
    AGILEX_B((byte) 0x36, "AgilexB", FPGA),
    MEV((byte) 0x01, "IPU ES2000", NIC),
    LKV((byte) 0x02, "Enet Controller E610", NIC),
    CNV((byte) 0x03, "Enet Controller E830", NIC);

    private final byte familyId;
    private final Integer asInteger;
    private final String asHex;
    private final String familyName;
    private final FamilyType familyType;

    Family(byte familyId, String familyName, FamilyType type) {
        this.familyId = familyId;
        this.asInteger = toUnsignedInt(familyId);
        this.asHex = toHex(this.asInteger);
        this.familyName = familyName;
        this.familyType = type;
    }

    public static Family from(String idHex) {
        return from(fromHexSingle(idHex));
    }

    public static Family from(byte id) {
        return from(toUnsignedInt(id));
    }

    public static Family from(Integer id) {
        return find(id).orElseThrow(UnknownFamilyIdException::new);
    }

    public static Optional<Family> find(Integer id) {
        return Arrays.stream(values())
            .filter(familyId -> familyId.asInteger.equals(id))
            .findFirst();
    }

    public static List<Integer> getAllIds(FamilyType type) {
        return Arrays.stream(Family.values())
            .filter(family -> type.equals(family.getFamilyType()))
            .map(Family::getAsInteger)
            .toList();
    }
}
