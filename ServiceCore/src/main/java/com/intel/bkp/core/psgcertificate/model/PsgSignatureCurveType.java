/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2022 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.core.psgcertificate.model;

import com.intel.bkp.crypto.curve.CurveSpec;
import com.intel.bkp.crypto.interfaces.ICurveSpec;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;

import static com.intel.bkp.crypto.constants.CryptoConstants.SHA256_WITH_ECDSA;
import static com.intel.bkp.crypto.constants.CryptoConstants.SHA384_WITH_ECDSA;

@Getter
@AllArgsConstructor
public enum PsgSignatureCurveType implements ICurveSpec {
    SECP256R1(CurveSpec.C256, 0x00113305, SHA256_WITH_ECDSA),
    SECP384R1(CurveSpec.C384, 0x30548820, SHA384_WITH_ECDSA);

    private final CurveSpec curveSpec;
    private final int magic;
    private final String bcAlgName;

    public static PsgSignatureCurveType fromMagic(int magic) {
        return Arrays.stream(values())
            .filter(val -> val.getMagic() == magic)
            .findFirst()
            .orElseThrow(IllegalArgumentException::new);
    }

    public static PsgSignatureCurveType fromCurveSpec(CurveSpec curveSpec) {
        return Arrays.stream(values())
            .filter(val -> val.getCurveSpec() == curveSpec)
            .findFirst()
            .orElseThrow(IllegalArgumentException::new);
    }
}
