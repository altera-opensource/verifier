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

import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EfuseChainParserTest {

    private static final String SUBJ_DICE_ROOT = "CN=Intel DICE Root";
    private static final String SUBJ_IPCS_SIGNING_CA = "CN=Intel:Agilex:IPCS";
    private static final String SUBJ_IPCS_DEVICE_ID = "CN=Intel:Agilex:L0:SKI:UID";
    private static final String SUBJ_FIRMWARE = "CN=Intel:Agilex:L1:SKI:UID";
    private static final String SUBJ_ALIAS = "CN=Intel:Agilex:L2:SKI:UID";

    @Mock
    private X509Certificate diceRoot;
    @Mock
    private X509Certificate ipcsSigningCaCert;
    @Mock
    private X509Certificate ipcsDeviceIdCert;
    @Mock
    private X509Certificate firmwareCert;
    @Mock
    private X509Certificate aliasCert;

    @Mock
    private X500Principal diceRootPrincipal;
    @Mock
    private X500Principal ipcsSigningCaCertPrincipal;
    @Mock
    private X500Principal ipcsDeviceIdCertPrincipal;
    @Mock
    private X500Principal firmwareCertPrincipal;
    @Mock
    private X500Principal aliasCertPrincipal;

    @Test
    void parseEfuseChain_WithCertsRootedToDiceRoot_Success() {
        // given
        mockCertificateChainRootedToDice();
        final List<X509Certificate> validChain = List.of(
            diceRoot, ipcsSigningCaCert, ipcsDeviceIdCert, firmwareCert, aliasCert);

        // when
        final EfuseChainParser result = EfuseChainParser.parseEfuseChain(validChain);

        // then
        assertEquals(ipcsDeviceIdCert, result.getDeviceIdCert());
        assertEquals(firmwareCert, result.getFirmwareCert());
        assertEquals(aliasCert, result.getAliasCert());
    }

    @Test
    void parseEfuseChain_WithCertsRootedToDiceRoot_ReversedOrder_Success() {
        // given
        mockIpcsDeviceIdCert();
        mockFirmwareCert();
        mockAliasCert();
        final List<X509Certificate> validChain = List.of(
            aliasCert, firmwareCert, ipcsDeviceIdCert, ipcsSigningCaCert, diceRoot);

        // when
        final EfuseChainParser result = EfuseChainParser.parseEfuseChain(validChain);

        // then
        assertEquals(ipcsDeviceIdCert, result.getDeviceIdCert());
        assertEquals(firmwareCert, result.getFirmwareCert());
        assertEquals(aliasCert, result.getAliasCert());
    }

    @Test
    void parseEfuseChain_WithoutDeviceIdCert_Throws() {
        // given
        mockDiceRootCert();
        mockFirmwareCert();
        mockAliasCert();
        final List<X509Certificate> invalidChain = List.of(diceRoot, firmwareCert, aliasCert);

        // when-then
        final VerifierRuntimeException exception =
            assertThrows(VerifierRuntimeException.class, () -> EfuseChainParser.parseEfuseChain(invalidChain));

        // then
        assertEquals("Certificate from level L0 not found.", exception.getMessage());
    }

    @Test
    void parseEfuseChain_WithoutFirmwareCert_Throws() {
        // given
        mockDiceRootCert();
        mockIpcsDeviceIdCert();
        mockAliasCert();
        final List<X509Certificate> invalidChain = List.of(diceRoot, ipcsDeviceIdCert, aliasCert);

        // when-then
        final VerifierRuntimeException exception =
            assertThrows(VerifierRuntimeException.class, () -> EfuseChainParser.parseEfuseChain(invalidChain));

        // then
        assertEquals("Certificate from level L1 not found.", exception.getMessage());
    }

    @Test
    void parseEfuseChain_WithoutAliasCert_Throws() {
        // given
        mockDiceRootCert();
        mockIpcsDeviceIdCert();
        mockFirmwareCert();
        final List<X509Certificate> invalidChain = List.of(diceRoot, ipcsDeviceIdCert, firmwareCert);

        // when-then
        final VerifierRuntimeException exception =
            assertThrows(VerifierRuntimeException.class, () -> EfuseChainParser.parseEfuseChain(invalidChain));

        // then
        assertEquals("Certificate from level L2 not found.", exception.getMessage());
    }

    @Test
    void parseEfuseChain_WithInsufficientSize_Throws() {
        // given
        final List<X509Certificate> tooSmallChain = List.of(diceRoot, ipcsSigningCaCert);

        // when-then
        final VerifierRuntimeException exception =
            assertThrows(VerifierRuntimeException.class, () -> EfuseChainParser.parseEfuseChain(tooSmallChain));

        // then
        assertEquals("Insufficient chain size from device: 2.", exception.getMessage());
    }

    private void mockCertificateChainRootedToDice() {
        mockDiceRootCert();
        mockIpcsSigningCaCert();
        mockIpcsDeviceIdCert();
        mockFirmwareCert();
        mockAliasCert();
    }

    private void mockDiceRootCert() {
        mockCertificate(diceRoot, diceRootPrincipal, SUBJ_DICE_ROOT);
    }

    private void mockIpcsSigningCaCert() {
        mockCertificate(ipcsSigningCaCert, ipcsSigningCaCertPrincipal, SUBJ_IPCS_SIGNING_CA);
    }

    private void mockIpcsDeviceIdCert() {
        mockCertificate(ipcsDeviceIdCert, ipcsDeviceIdCertPrincipal, SUBJ_IPCS_DEVICE_ID);
    }

    private void mockFirmwareCert() {
        mockCertificate(firmwareCert, firmwareCertPrincipal, SUBJ_FIRMWARE);
    }

    private void mockAliasCert() {
        mockCertificate(aliasCert, aliasCertPrincipal, SUBJ_ALIAS);
    }

    private void mockCertificate(X509Certificate certificate, X500Principal certificatePrincipal, String subject) {
        when(certificate.getSubjectX500Principal()).thenReturn(certificatePrincipal);
        when(certificatePrincipal.getName()).thenReturn(subject);
    }
}
