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

package com.intel.bkp.core.psgcertificate.verify;

import com.intel.bkp.core.TestUtil;
import com.intel.bkp.core.psgcertificate.PsgPublicKeyBuilder;
import com.intel.bkp.core.psgcertificate.PsgSignatureBuilder;
import com.intel.bkp.core.psgcertificate.PsgSignatureHelper;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.crypto.constants.CryptoConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_384;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PsgSignatureVerifierTest {

    private static final byte[] PAYLOAD_FOR_SIGNATURE = new byte[48];
    private static final byte[] DIFFERENT_PAYLOAD = new byte[32];

    @Mock
    private PsgPublicKeyBuilder psgPublicKeyBuilder;

    @Mock
    private PsgSignatureBuilder psgSignatureBuilder;

    private final KeyPair kp = TestUtil.genEcKeys(EC_CURVE_SPEC_384);
    private final byte[] signature = TestUtil.signEcData(PAYLOAD_FOR_SIGNATURE,
        kp.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA);

    @Test
    public void isValid_ReturnsTrue() throws Exception {
        // given
        mockPublicKeyBuilder();

        // when
        boolean result = PsgSignatureVerifier.isValid(psgPublicKeyBuilder, psgSignatureBuilder, PAYLOAD_FOR_SIGNATURE);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    public void isValid_NotValidSignature_ReturnsFalse() throws Exception {
        // given
        mockPublicKeyBuilder();

        // when
        boolean result = PsgSignatureVerifier.isValid(psgPublicKeyBuilder, psgSignatureBuilder, DIFFERENT_PAYLOAD);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    public void isValid_PublicKeyNotCorrect_Throws() throws Exception {
        // given
        when(psgPublicKeyBuilder.withActor(any())).thenReturn(psgPublicKeyBuilder);
        doThrow(new PsgCertificateException("message")).when(psgPublicKeyBuilder).verify();

        // when-then
        Assertions.assertThrows(PsgCertificateException.class,
            () -> PsgSignatureVerifier.isValid(psgPublicKeyBuilder, psgSignatureBuilder, PAYLOAD_FOR_SIGNATURE));
    }

    private ECPoint getW() {
        return ((ECPublicKey) kp.getPublic()).getW();
    }

    private void mockPublicKeyBuilder() {
        when(psgPublicKeyBuilder.withActor(any())).thenReturn(psgPublicKeyBuilder);
        when(psgPublicKeyBuilder.getCurveType()).thenReturn(PsgCurveType.SECP384R1);
        when(psgPublicKeyBuilder.getPointX()).thenReturn(getW().getAffineX().toByteArray());
        when(psgPublicKeyBuilder.getPointY()).thenReturn(getW().getAffineY().toByteArray());
        when(psgSignatureBuilder.getSignatureType()).thenReturn(PsgSignatureCurveType.SECP384R1);
        when(psgSignatureBuilder.getSignatureR()).thenReturn(PsgSignatureHelper.extractR(signature));
        when(psgSignatureBuilder.getSignatureS()).thenReturn(PsgSignatureHelper.extractS(signature));
    }
}
