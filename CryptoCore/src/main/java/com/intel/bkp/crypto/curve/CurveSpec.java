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

package com.intel.bkp.crypto.curve;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.CurveNameMappingException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.security.PublicKey;
import java.util.Arrays;

@AllArgsConstructor
@Getter
@ToString
public enum CurveSpec {
    C256(32, CryptoConstants.EC_CURVE_SPEC_256),
    C384(48, CryptoConstants.EC_CURVE_SPEC_384),
    C521(66, CryptoConstants.EC_CURVE_SPEC_521);

    private final int size;
    @ToString.Exclude
    private final String bcCurveTypeEc;

    public static CurveSpec fromBcCurveTypeEc(String bcCurveTypeEc) {
        return Arrays.stream(values())
            .filter(val -> val.getBcCurveTypeEc().equals(bcCurveTypeEc))
            .findFirst()
            .orElseThrow(IllegalArgumentException::new);
    }

    public static CurveSpec getCurveSpec(PublicKey ecPublicKey) {
        final String ecCurveName = getEcCurveName(ecPublicKey);
        return CurveSpec.fromBcCurveTypeEc(ecCurveName);
    }

    private static String getEcCurveName(PublicKey ecPublicKey) {
        try {
            return ((ECNamedCurveParameterSpec) ((BCECPublicKey) ecPublicKey).getParameters()).getName();
        } catch (Exception ex) {
            throw new CurveNameMappingException("Failed to detect ec curve name", ex);
        }
    }
}
