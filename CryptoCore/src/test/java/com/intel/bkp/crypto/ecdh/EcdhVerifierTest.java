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

package com.intel.bkp.crypto.ecdh;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.impl.EcUtils;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class EcdhVerifierTest {

    @Mock
    private ECPrivateKey privateKey;

    @Mock
    private ECParameterSpec ecParameterSpec;

    private BigInteger order = BigInteger.TEN;

    private Provider provider = CryptoUtils.getBouncyCastleProvider();

    @BeforeEach
    public void setup() {
        when(privateKey.getParams()).thenReturn(ecParameterSpec);
        when(ecParameterSpec.getOrder()).thenReturn(order);
    }

    @Test
    public void isValid() throws KeystoreGenericException {
        // given
        KeyPair keyPair = CryptoUtils.genEcdhBC();

        // when
        boolean result = EcdhVerifier.isValid((ECPrivateKey)keyPair.getPrivate());

        // then
        Assertions.assertTrue(result);
    }

    @Test
    public void isValid_IsOne_ReturnsFalse() {
        // given
        when(privateKey.getS()).thenReturn(BigInteger.ONE);

        // when
        boolean result = EcdhVerifier.isValid(privateKey);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    public void isValid_IsLessThanOne_ReturnsFalse() {
        // given
        when(privateKey.getS()).thenReturn(BigInteger.ZERO);

        // when
        boolean result = EcdhVerifier.isValid(privateKey);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    public void isValid_IsGroupOrder_ReturnsFalse() {
        // given
        when(privateKey.getS()).thenReturn(order);

        // when
        boolean result = EcdhVerifier.isValid(privateKey);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    public void isValid_IsGreaterThanGroupOrder_ReturnsFalse() {
        // given
        when(privateKey.getS()).thenReturn(order.add(BigInteger.ONE));

        // when
        boolean result = EcdhVerifier.isValid(privateKey);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    public void isValidFromXY_Ec384_ReturnsTrue() throws KeystoreGenericException {
        // given
        String curveType = CryptoConstants.EC_CURVE_SPEC_384;
        KeyPair keyPair = EcUtils.genEc(provider, CryptoConstants.ECDH_KEY, curveType);
        java.security.spec.ECPoint point = ((ECPublicKey) keyPair.getPublic()).getW();
        BigInteger affineX = point.getAffineX();
        BigInteger affineY = point.getAffineY();

        // when
        boolean result = EcdhVerifier.isValid(affineX, affineY, curveType);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    public void isValidFromXY_Ec256_ReturnsTrue() throws KeystoreGenericException {
        // given
        String curveType = CryptoConstants.EC_CURVE_SPEC_256;
        KeyPair keyPair = EcUtils.genEc(provider, CryptoConstants.ECDH_KEY, curveType);
        java.security.spec.ECPoint point = ((ECPublicKey) keyPair.getPublic()).getW();
        BigInteger affineX = point.getAffineX();
        BigInteger affineY = point.getAffineY();

        // when
        boolean result = EcdhVerifier.isValid(affineX, affineY, curveType);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    public void isValidFromXY_XIsNull_ReturnsFalse() {
        // when
        boolean result = EcdhVerifier.isValid(null, null, CryptoConstants.EC_CURVE_SPEC_384);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    public void isValidFromXY_YIsNull_ReturnsFalse() {
        // given
        BigInteger affineX = BigInteger.TWO;

        // when
        boolean result = EcdhVerifier.isValid(affineX, null, CryptoConstants.EC_CURVE_SPEC_384);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    public void isValidFromXY_XYNotNull_ReturnsBecausePointIsNotValid() {
        // given
        BigInteger affineX = BigInteger.TWO;
        BigInteger affineY = BigInteger.TEN;

        // when
        boolean result = EcdhVerifier.isValid(affineX, affineY, CryptoConstants.EC_CURVE_SPEC_384);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    public void isValidFromXY_PointGenerator_ReturnsFalse() {
        // given
        ECPoint curveGenerator = CryptoUtils.getCurveGenerator(CryptoConstants.EC_CURVE_SPEC_384);
        BigInteger affineX = curveGenerator.getAffineXCoord().toBigInteger();
        BigInteger affineY = curveGenerator.getAffineYCoord().toBigInteger();

        // when
        boolean result = EcdhVerifier.isValid(affineX, affineY, CryptoConstants.EC_CURVE_SPEC_384);

        // then
        Assertions.assertFalse(result);
    }
}
