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

package com.intel.bkp.core.utils;

import com.intel.bkp.core.exceptions.PublicKeyHelperException;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.crypto.curve.EcSignatureAlgorithm;
import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import lombok.Getter;
import org.bouncycastle.math.ec.ECCurve;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.function.Function;

import static com.intel.bkp.crypto.CryptoUtils.getBouncyCastleProvider;
import static com.intel.bkp.crypto.CryptoUtils.getEcKeySpec;
import static com.intel.bkp.utils.PaddingUtils.padLeft;

@Getter
public class PublicKeyHelperBase {

    private final CurvePoint point;
    private final BigInteger affineX;
    private final BigInteger affineY;

    public PublicKeyHelperBase(CurvePoint point) {
        this.point = point;
        this.affineX = ensurePositivePointValue(CurvePoint::getPointA);
        this.affineY = ensurePositivePointValue(CurvePoint::getPointB);
    }

    public void verifyPoint() throws PublicKeyHelperException {
        final boolean isValid;
        try {
            final EcSignatureAlgorithm ecSignatureAlgorithm = EcSignatureAlgorithm.fromCurveSpec(point.getCurveSpec());
            final ECCurve.AbstractFp ctor = ecSignatureAlgorithm.getCurveClass().getDeclaredConstructor().newInstance();
            isValid = ctor.createPoint(getAffineX(), getAffineY()).isValid();
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException
                 | NoSuchMethodException e) {
            throw new PublicKeyHelperException("PublicKey is not valid - wrong curve definition");
        }

        if (!isValid) {
            throw new PublicKeyHelperException("PublicKey is not valid - wrong curve point");
        }
    }

    public PublicKey toPublic() throws PublicKeyHelperException {
        try {
            final ECPublicKeySpec keySpec = getEcKeySpec(getAffineX(), getAffineY(),
                getPoint().getCurveSpec().getBcCurveTypeEc());
            final KeyFactory kf = KeyFactory.getInstance(CryptoConstants.EC_KEY, getBouncyCastleProvider());
            return kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new PublicKeyHelperException("Failed to convert data to public key", e);
        }
    }

    public String toPublicPem() throws PublicKeyHelperException {
        return PemFormatEncoder.encode(PemFormatHeader.PUBLIC_KEY, toPublic().getEncoded());
    }

    private BigInteger ensurePositivePointValue(Function<CurvePoint, byte[]> getBytes) {
        final CurvePoint point = getPoint();
        return new BigInteger(padLeft(getBytes.apply(point), point.getCurveSpec().getSize() + 1));
    }
}
