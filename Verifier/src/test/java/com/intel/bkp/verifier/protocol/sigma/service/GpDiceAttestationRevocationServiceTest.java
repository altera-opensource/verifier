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

package com.intel.bkp.verifier.protocol.sigma.service;

import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.fpgacerts.dp.DistributionPointCrlProvider;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.service.certificate.AppContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GpDiceAttestationRevocationServiceTest {

    private static final String CERT_PATH = "path";
    private static final String DICE_ROOT_HASH = "dice";
    private static final String[] TRUSTED_ROOT_HASH = new String[]{"", DICE_ROOT_HASH};

    @Mock
    private AppContext appContext;

    @Mock
    private LibConfig libConfig;

    @Mock
    private DistributionPointConnector dpConnector;

    private GpDiceAttestationRevocationService sut;

    @Test
    void constructor_configuresProperly() {
        // given
        when(appContext.getDpConnector()).thenReturn(dpConnector);
        when(appContext.getDpTrustedRootHashes()).thenReturn(TRUSTED_ROOT_HASH);
        when(appContext.getDpPathCer()).thenReturn(CERT_PATH);
        when(appContext.getLibConfig()).thenReturn(libConfig);
        when(libConfig.isTestModeSecrets()).thenReturn(true);

        // when
        sut = new GpDiceAttestationRevocationService(appContext);

        // then
        final var diceCertVerifier = sut.getDiceAliasChainVerifier();
        assertEquals(DICE_ROOT_HASH, diceCertVerifier.getTrustedRootHash()[1]);

        final var crlProvider = diceCertVerifier.getCrlVerifier().getCrlProvider();
        assertTrue(crlProvider instanceof DistributionPointCrlProvider);

        final var addressProvider = sut.getAddressProvider();
        assertEquals(CERT_PATH, addressProvider.getIpcsUrlPrefix());

        verify(appContext, times(2)).getDpConnector();
    }
}
