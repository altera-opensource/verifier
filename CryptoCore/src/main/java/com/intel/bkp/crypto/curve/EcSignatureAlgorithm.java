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
import com.intel.bkp.crypto.interfaces.ICurveSpec;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Curve;

import java.util.Arrays;

@Getter
@AllArgsConstructor
public enum EcSignatureAlgorithm implements ICurveSpec {

    ECDSA_P256(CurveSpec.C256, SecP256R1Curve.class, CryptoConstants.SHA256_WITH_ECDSA),
    ECDSA_P384(CurveSpec.C384, SecP384R1Curve.class, CryptoConstants.SHA384_WITH_ECDSA),
    ECDSA_P521(CurveSpec.C521, SecP521R1Curve.class, CryptoConstants.SHA512_WITH_ECDSA);

    private final CurveSpec curveSpec;
    private final Class<? extends ECCurve.AbstractFp> curveClass;
    private final String bcAlgName;

    public static EcSignatureAlgorithm fromCurveSpec(CurveSpec curveSpec) {
        return Arrays.stream(values())
            .filter(val -> val.getCurveSpec() == curveSpec)
            .findFirst()
            .orElseThrow(IllegalArgumentException::new);
    }
}
