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

package com.intel.bkp.verifier.protocol.spdm.service;

import com.intel.bkp.fpgacerts.dp.DistributionPointCrlProvider;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.certificate.DiceAliasChainVerifier;
import com.intel.bkp.verifier.service.certificate.DiceChainType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;

import static com.intel.bkp.test.CertificateUtils.readCertificate;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmDiceAttestationRevocationServiceTest {

    private static final String DICE_ROOT_HASH = "dice";
    private static final String[] TRUSTED_ROOT_HASH = new String[]{"", DICE_ROOT_HASH};
    private static final byte[] DEVICE_ID = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    private static final String ALIAS_EFUSE_FOLDER = "certs/dice/aliasEfuseChain/";

    @Mock
    private AppContext appContext;

    @Mock
    private LibConfig libConfig;

    @Mock
    private DiceAliasChainVerifier diceAliasChainVerifier;

    private SpdmDiceAttestationRevocationService sut;

    @Test
    void constructor_configuresProperly() {
        // given
        when(appContext.getDpTrustedRootHashes()).thenReturn(TRUSTED_ROOT_HASH);
        when(appContext.getLibConfig()).thenReturn(libConfig);
        when(libConfig.isTestModeSecrets()).thenReturn(true);

        // when
        sut = new SpdmDiceAttestationRevocationService(appContext);

        // then
        final var diceCertVerifier = sut.getDiceAliasChainVerifier();
        assertEquals(DICE_ROOT_HASH, diceCertVerifier.getTrustedRootHash()[1]);

        final var crlProvider = diceCertVerifier.getCrlVerifier().getCrlProvider();
        assertTrue(crlProvider instanceof DistributionPointCrlProvider);
    }

    @Test
    void verifyChain_CallsVerifyChain() {
        // given
        final var sut = new SpdmDiceAttestationRevocationService(diceAliasChainVerifier);
        final X509Certificate efuseCert = readCertificate(ALIAS_EFUSE_FOLDER, "UDS_EFUSE_ALIAS_3AB5A0DC4DE7CB08.cer");
        final List<X509Certificate> certChain = List.of(efuseCert);
        final var chainHolder = new SpdmCertificateChainHolder(1, DiceChainType.ATTESTATION, certChain);

        // when-then
        assertDoesNotThrow(() -> sut.verifyChain(DEVICE_ID, chainHolder));

        // then
        verify(diceAliasChainVerifier).verifyChain(certChain);
    }

}
