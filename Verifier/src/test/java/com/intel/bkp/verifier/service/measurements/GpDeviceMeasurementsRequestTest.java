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

package com.intel.bkp.verifier.service.measurements;

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.verifier.database.model.S10CacheEntity;
import com.intel.bkp.verifier.exceptions.SigmaException;
import com.intel.bkp.verifier.model.RootChainType;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_384;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_KEY;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GpDeviceMeasurementsRequestTest {

    private static final byte[] DEVICE_ID = {1, 2, 3};
    private static final PufType PUF_TYPE = PufType.INTEL_USER;
    private static final String CONTEXT = "context";
    private static final Integer COUNTER = 3;
    private static final byte[] ALIAS_XY = {4, 5, 6};

    private static MockedStatic<CryptoUtils> cryptoUtilsMockStatic;

    @Mock
    private PublicKey aliasPubKey;

    @BeforeAll
    public static void prepareStaticMock() {
        cryptoUtilsMockStatic = mockStatic(CryptoUtils.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        cryptoUtilsMockStatic.close();
    }

    @Test
    void forDice_Success() {
        // when
        final var result = GpDeviceMeasurementsRequest.forDice(DEVICE_ID, aliasPubKey, PUF_TYPE);

        // then
        Assertions.assertEquals(DEVICE_ID, result.getDeviceId());
        Assertions.assertEquals(RootChainType.MULTI, result.getChainType());
        Assertions.assertEquals(aliasPubKey, result.getAliasPubKey());
        Assertions.assertEquals(PUF_TYPE, result.getPufType());
        Assertions.assertEquals("", result.getContext());
        Assertions.assertEquals(0, result.getCounter());
    }

    @Test
    void forS10_Success() {
        // given
        mockConversionToEcPublicKey(ALIAS_XY, aliasPubKey);
        final var s10CacheEntity = new S10CacheEntity(
            toHex(DEVICE_ID), CONTEXT, COUNTER, PUF_TYPE.name(), toHex(ALIAS_XY));

        // when
        final var result = GpDeviceMeasurementsRequest.forS10(DEVICE_ID, s10CacheEntity);

        // then
        Assertions.assertEquals(DEVICE_ID, result.getDeviceId());
        Assertions.assertEquals(RootChainType.SINGLE, result.getChainType());
        Assertions.assertEquals(aliasPubKey, result.getAliasPubKey());
        Assertions.assertEquals(PUF_TYPE, result.getPufType());
        Assertions.assertEquals(CONTEXT, result.getContext());
        Assertions.assertEquals(COUNTER, result.getCounter());
    }

    @Test
    void forS10_InvalidAliasKeyBytes_ThrowsSigmaException() {
        // given
        final byte[] incorrectAliasXY = {7, 8, 9};
        mockConversionToEcPublicKeyThrows(incorrectAliasXY);
        final var s10CacheEntity = new S10CacheEntity(
            toHex(DEVICE_ID), CONTEXT, COUNTER, PUF_TYPE.name(), toHex(incorrectAliasXY));

        // when-then
        Assertions.assertThrows(SigmaException.class,
            () -> GpDeviceMeasurementsRequest.forS10(DEVICE_ID, s10CacheEntity));
    }

    @SneakyThrows
    private void mockConversionToEcPublicKey(byte[] keyBytes, PublicKey resultKey) {
        when(CryptoUtils.toEcPublicBC(keyBytes, EC_KEY, EC_CURVE_SPEC_384)).thenReturn(resultKey);
    }

    @SneakyThrows
    private void mockConversionToEcPublicKeyThrows(byte[] keyBytes) {
        when(CryptoUtils.toEcPublicBC(keyBytes, EC_KEY, EC_CURVE_SPEC_384)).thenThrow(new InvalidKeySpecException());
    }
}
