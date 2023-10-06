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

package com.intel.bkp.fpgacerts.url.params.parsing;

import com.intel.bkp.fpgacerts.exceptions.InvalidDiceCertificateSubjectException;
import com.intel.bkp.fpgacerts.exceptions.X509Exception;
import com.intel.bkp.fpgacerts.url.params.DiceParams;
import com.intel.bkp.test.CertificateUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiceParamsIssuerParserTest {

    private static final String TEST_FOLDER = "certs/dice/";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final String EXPECTED_SKI = "DI931bRmuixmLyW4WJYySeQiDaQ";
    private static final String EXPECTED_UID = "065effc1e44f3506";
    private static final String AKI_OID = Extension.authorityKeyIdentifier.getId();

    private static X509Certificate firmwareCert;

    @Mock
    private static X509Certificate certificate;

    private DiceParamsIssuerParser sut;

    @BeforeAll
    static void init() {
        firmwareCert = CertificateUtils.readCertificate(TEST_FOLDER, FIRMWARE_CERT);
    }

    @BeforeEach
    void setUp() {
        sut = new DiceParamsIssuerParser();
    }


    @Test
    void parse() {
        // when
        final DiceParams result = sut.parse(firmwareCert);

        // then
        assertEquals(EXPECTED_SKI, result.getId());
        assertEquals(EXPECTED_UID, result.getUid());
    }

    @Test
    void parse_certWithoutAki_Throws() {
        // given
        when(certificate.getExtensionValue(AKI_OID)).thenReturn(null);

        // when-then
        assertThrows(X509Exception.class, () -> sut.parse(certificate));
    }

    @Test
    void parse_certWithIssuerDNThatIsNotInDiceFormat_Throws() {
        // given
        when(certificate.getExtensionValue(AKI_OID)).thenReturn(firmwareCert.getExtensionValue(AKI_OID));
        mockIssuer(certificate, "CN=ValidCommonName:ButNotInDiceFormat");

        // when-then
        assertThrows(InvalidDiceCertificateSubjectException.class, () -> sut.parse(certificate));
    }

    private void mockIssuer(X509Certificate cert, String issuer) {
        final X500Principal principal = mock(X500Principal.class);
        when(cert.getIssuerX500Principal()).thenReturn(principal);
        when(principal.getName()).thenReturn(issuer);
    }
}
