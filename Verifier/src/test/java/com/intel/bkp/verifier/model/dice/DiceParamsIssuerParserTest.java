/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.model.dice;

import com.intel.bkp.ext.core.exceptions.InvalidDiceCertificateSubjectException;
import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.exceptions.X509ParsingException;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.Principal;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiceParamsIssuerParserTest {

    private static final String TEST_FOLDER = "responses/";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final String EXPECTED_SKI = "DI931bRmuixmLyW4WJYySeQiDaQ";
    private static final String EXPECTED_UID = "065effc1e44f3506";
    private static final X509CertificateParser X509_PARSER = new X509CertificateParser();
    private static final String AKI_OID = Extension.authorityKeyIdentifier.getId();

    private static X509Certificate firmwareCert;

    @Mock
    private static X509Certificate certificate;

    @Mock
    private static Principal principal;

    private DiceParamsIssuerParser sut;

    @BeforeAll
    static void init() throws Exception {
        firmwareCert = X509_PARSER.toX509(readCertificate(FIRMWARE_CERT));
    }

    @BeforeEach
    void setUp() {
        sut = new DiceParamsIssuerParser();
    }

    private static byte[] readCertificate(String filename) throws Exception {
        return Utils.readFromResources(TEST_FOLDER, filename);
    }

    @Test
    void parse() {
        // when
        final DiceParams result = sut.parse(firmwareCert);

        // then
        Assertions.assertEquals(EXPECTED_SKI, result.getSki());
        Assertions.assertEquals(EXPECTED_UID, result.getUid());
    }

    @Test
    void parse_certWithoutAki_Throws() {
        // given
        when(certificate.getExtensionValue(AKI_OID)).thenReturn(null);

        // when-then
        Assertions.assertThrows(X509ParsingException.class, () -> sut.parse(certificate));
    }

    @Test
    void parse_certWithIssuerDNThatIsNotInDiceFormat_Throws() {
        // given
        when(certificate.getIssuerDN()).thenReturn(principal);
        when(principal.getName()).thenReturn("CN=ValidCommonName:ButNotInDiceFormat");
        when(certificate.getExtensionValue(AKI_OID)).thenReturn(firmwareCert.getExtensionValue(AKI_OID));

        // when-then
        Assertions.assertThrows(InvalidDiceCertificateSubjectException.class, () -> sut.parse(certificate));
    }
}
