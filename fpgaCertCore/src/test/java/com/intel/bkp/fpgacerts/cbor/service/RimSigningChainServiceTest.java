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

package com.intel.bkp.fpgacerts.cbor.service;

import com.intel.bkp.fpgacerts.dp.DistributionPointChainFetcher;
import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.fpgacerts.dp.DistributionPointCrlProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.matches;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RimSigningChainServiceTest {

    private static final String CERTIFICATE_PATH_REGEX =
        "http://localhost:9090/content/IPCS/certs/RIM_Signing_agilex_.*\\.cer";

    @Mock
    private DistributionPointChainFetcher chainFetcher;

    @Mock
    private RimSigningChainVerifier chainVerifier;

    @Mock
    private DistributionPointConnector dpConnector;

    @Mock
    private X509Certificate x509Certificate;

    @Mock
    private PublicKey pubKey;

    @Spy
    private LinkedList<X509Certificate> list = new LinkedList<>();

    private RimSigningChainService sut;

    @BeforeEach
    void prepareSut() {
        sut = new RimSigningChainService(chainFetcher, chainVerifier);
    }

    @Test
    void constructor_Success() {
        // when
        final RimSigningChainService actual = new RimSigningChainService(dpConnector, new String[]{"testRootHash"});

        // then
        assertNotNull(actual);
    }

    @Test
    void constructor_WithChainFetcher_Success() {
        // when
        final RimSigningChainService actual = new RimSigningChainService(chainFetcher,
            new DistributionPointCrlProvider(dpConnector), new String[]{"testRootHash"});

        // then
        assertNotNull(actual);
    }

    @Test
    void verifyRimSigningChainAndGetRimSigningKey_Success() {
        // given
        final var url = "http://localhost:9090/content/IPCS/certs/RIM_Signing_agilex_5WL28Ty-Nta3Si1dR3ralQ7jFHw.cer";
        list.add(x509Certificate);
        when(chainFetcher.downloadCertificateChainAsX509(matches(CERTIFICATE_PATH_REGEX))).thenReturn(list);
        doNothing().when(chainVerifier).verifyChain(List.of(x509Certificate));
        when(x509Certificate.getPublicKey()).thenReturn(pubKey);

        // when
        var result = sut.verifyRimSigningChainAndGetRimSigningKey(url);

        // then
        assertEquals(pubKey, result);
    }
}
