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

import com.intel.bkp.core.properties.TrustedRootHash;
import com.intel.bkp.verifier.dp.DistributionPointConnector;
import com.intel.bkp.verifier.model.LibConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiceAttestationRevocationServiceTest {

    @InjectMocks
    private DiceAttestationRevocationService sut;

    @Test
    void constructor_configuresProperly() {
        // given
        final var appContext = mock(AppContext.class);
        final var libConfig = mock(LibConfig.class);
        final var dpConnector = mock(DistributionPointConnector.class);
        final var certPath = "path";
        final var diceRootHash = "dice";
        final var trustedRootHash = new TrustedRootHash("", diceRootHash);

        when(appContext.getDpConnector()).thenReturn(dpConnector);
        when(appContext.getDpTrustedRootHash()).thenReturn(trustedRootHash);
        when(appContext.getDpPathCer()).thenReturn(certPath);
        when(appContext.getLibConfig()).thenReturn(libConfig);
        when(libConfig.isTestModeSecrets()).thenReturn(true);

        // when
        sut = new DiceAttestationRevocationService(appContext);

        // then
        final var diceCertVerifier = sut.getDiceAliasChainVerifier();
        Assertions.assertEquals(diceRootHash, diceCertVerifier.getTrustedRootHash());

        final var crlProvider = diceCertVerifier.getCrlVerifier().getCrlProvider();
        Assertions.assertTrue(crlProvider instanceof DistributionPointCrlProvider);

        final var addressProvider = sut.getAddressProvider();
        Assertions.assertEquals(certPath, addressProvider.getCertificateUrlPrefix());

        verify(appContext, times(2)).getDpConnector();
    }
}
