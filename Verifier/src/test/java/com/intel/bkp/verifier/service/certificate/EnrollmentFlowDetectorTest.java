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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.dice.IpcsCertificateFetcher;
import com.intel.bkp.fpgacerts.exceptions.IpcsCertificateFetcherNotInitializedException;
import com.intel.bkp.verifier.database.SQLiteHelper;
import com.intel.bkp.verifier.database.repository.DiceRevocationCacheEntityService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EnrollmentFlowDetectorTest {

    private static final byte[] DEVICE_ID = {1, 2, 3, 4, 5, 6, 7, 8};

    private static MockedStatic<AppContext> appContextMockStatic;

    @Mock
    private AppContext appContext;

    @Mock
    private DistributionPointCertificate deviceIdCert;

    @Mock
    private IpcsCertificateFetcher certFetcher;

    @Mock
    private DiceRevocationCacheService diceRevocationCacheService;

    private EnrollmentFlowDetector sut;

    @BeforeAll
    public static void prepareStaticMock() {
        appContextMockStatic = mockStatic(AppContext.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        appContextMockStatic.close();
    }

    @BeforeEach
    void initSut() {
        sut = new EnrollmentFlowDetector(DEVICE_ID, certFetcher, diceRevocationCacheService);
    }

    @Test
    void instance_DoesNotThrow() {
        // given
        mockAppContext();

        // when
        Assertions.assertDoesNotThrow(() -> EnrollmentFlowDetector.instance(DEVICE_ID, certFetcher));
    }

    @Test
    void isEnrollmentFlow_RevokedDevice_ReturnsTrue() {
        // given
        when(diceRevocationCacheService.isRevoked(DEVICE_ID)).thenReturn(true);

        // when
        final boolean result = sut.isEnrollmentFlow();

        // then
        Assertions.assertTrue(result);
        verifyNoInteractions(certFetcher);
    }

    @Test
    void isEnrollmentFlow_NotRevokedDevice_DeviceIdCertDoesNotExist_ReturnsTrue() {
        // given
        when(diceRevocationCacheService.isRevoked(DEVICE_ID)).thenReturn(false);
        when(certFetcher.fetchIpcsDeviceIdCert()).thenReturn(Optional.empty());

        // when
        final boolean result = sut.isEnrollmentFlow();

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void isEnrollmentFlow_NotRevokedDevice_DeviceIdCertExists_ReturnsFalse() {
        // given
        when(diceRevocationCacheService.isRevoked(DEVICE_ID)).thenReturn(false);
        when(certFetcher.fetchIpcsDeviceIdCert()).thenReturn(Optional.of(deviceIdCert));

        // when
        final boolean result = sut.isEnrollmentFlow();

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void isEnrollmentFlow_NotRevokedDevice_CertFetcherNotInitialized_Throws() {
        // given
        when(diceRevocationCacheService.isRevoked(DEVICE_ID)).thenReturn(false);
        when(certFetcher.fetchIpcsDeviceIdCert()).thenThrow(IpcsCertificateFetcherNotInitializedException.class);

        // when - then
        Assertions.assertThrows(IpcsCertificateFetcherNotInitializedException.class, () -> sut.isEnrollmentFlow());
    }

    private void mockAppContext() {
        when(AppContext.instance()).thenReturn(appContext);
        final var sqLiteHelper = mock(SQLiteHelper.class);
        when(appContext.getSqLiteHelper()).thenReturn(sqLiteHelper);
        final var diceRevocationCacheEntityService = mock(DiceRevocationCacheEntityService.class);
        when(sqLiteHelper.getDiceRevocationCacheEntityService()).thenReturn(diceRevocationCacheEntityService);
    }
}
