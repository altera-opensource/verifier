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

package com.intel.bkp.crypto.x509.utils;

import com.intel.bkp.crypto.TestUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Optional;

class AuthorityInformationAccessUtilsTest {

    private static final String CERT_WITH_AIA_EXTENSION = "IPCSSigningCA.cer";
    private static final String CERT_WITHOUT_AIA_EXTENSION = "root-ca.crt";

    private static final String ISSUER_URL = "https://tsci.intel.com/content/IPCS/certs/IPCS.cer";

    private static X509Certificate certWithAia;
    private static X509Certificate certWithoutAia;

    @BeforeAll
    static void init() throws Exception {
        certWithAia = TestUtil.loadCertificate(CERT_WITH_AIA_EXTENSION);
        certWithoutAia = TestUtil.loadCertificate(CERT_WITHOUT_AIA_EXTENSION);
    }

    @Test
    void getIssuerCertUrl_NoAiaExtension_Success() {
        // when
        final Optional<String> result = AuthorityInformationAccessUtils.getIssuerCertUrl(certWithoutAia);

        // then
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void getIssuerCertUrl_Success() {
        // when
        final Optional<String> result = AuthorityInformationAccessUtils.getIssuerCertUrl(certWithAia);

        // then
        Assertions.assertTrue(result.isPresent());
        Assertions.assertEquals(ISSUER_URL, result.get());
    }

}
