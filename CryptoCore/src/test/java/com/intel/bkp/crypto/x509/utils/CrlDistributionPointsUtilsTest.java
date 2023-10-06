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

package com.intel.bkp.crypto.x509.utils;

import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrlDistributionPointsUtilsTest {

    private static final String CERT_WITH_CRL_EXTENSION_AND_CRL_URL = "leaf-not-revoked.crt";
    private static final String CERT_WITH_CRL_EXTENSION_AND_EMPTY_URL = "leaf-crl-empty-path.crt";
    private static final String CERT_WITHOUT_CRL_EXTENSION = "leaf-no-crl.crt";

    private static final String CRL_URL = "http://green.no/ca/email-ca.crl";

    private static X509Certificate certWithCrlUrl;
    private static X509Certificate certWithEmptyCrlUrl;
    private static X509Certificate certWithoutCrlExtension;


    @BeforeAll
    static void init() throws Exception {
        // certificate chain generated based on tutorial https://pki-tutorial.readthedocs.io/en/latest/advanced/
        certWithCrlUrl = FileUtils.loadCertificate(CERT_WITH_CRL_EXTENSION_AND_CRL_URL);
        certWithEmptyCrlUrl = FileUtils.loadCertificate(CERT_WITH_CRL_EXTENSION_AND_EMPTY_URL);
        certWithoutCrlExtension = FileUtils.loadCertificate(CERT_WITHOUT_CRL_EXTENSION);
    }

    @Test
    void getCrlUrl_withCrlUrl() {
        // when
        Optional<String> result = CrlDistributionPointsUtils.getCrlUrl(certWithCrlUrl);

        // then
        assertTrue(result.isPresent());
        assertEquals(CRL_URL, result.get());
    }

    @Test
    void getCrlUrl_withEmptyCrlPath() {
        // when
        Optional<String> result = CrlDistributionPointsUtils.getCrlUrl(certWithEmptyCrlUrl);

        // then
        assertTrue(result.isEmpty());
    }

    @Test
    void getCrlUrl_withoutCrlExtension() {
        // when
        Optional<String> result = CrlDistributionPointsUtils.getCrlUrl(certWithoutCrlExtension);

        // then
        assertTrue(result.isEmpty());
    }
}
