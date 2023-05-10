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

package com.intel.bkp.verifier.x509;

import com.intel.bkp.crypto.x509.utils.AuthorityInformationAccessUtils;
import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.exceptions.X509ParsingException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.mockito.Mockito.mockStatic;

@ExtendWith(MockitoExtension.class)
class X509UtilsWrapperTest {

    private static final String TEST_FOLDER = "certs/";

    // https://tsci.intel.com/content/IPCS/certs/IPCSSigningCA.cer
    private static final String PARENT_CERT_FILENAME = "IPCSSigningCA.cer";
    private static final String CERT_SUBJECT = "CN=IPCS Signing Cert Test, OU=Intel PUF Certificate Service, "
        + "O=Intel Corporation, L=Santa Clara, ST=CA, C=US";
    private static final String ISSUER_URL = "https://tsci.intel.com/content/IPCS/certs/IPCS.cer";

    private static byte[] certificate;

    @BeforeAll
    static void init() throws Exception {
        certificate = Utils.readFromResources(TEST_FOLDER, PARENT_CERT_FILENAME);
    }

    @Test
    void toX509_Success() {
        // when
        X509Certificate result = X509UtilsWrapper.toX509(certificate);

        // then
        Assertions.assertEquals(CERT_SUBJECT, result.getSubjectX500Principal().toString());
    }

    @Test
    void toX509_ParsingFailed_Throws() {
        // when-then
        Assertions.assertThrows(X509ParsingException.class, () -> X509UtilsWrapper.toX509(new byte[]{1, 2}));
    }

    @Test
    void getIssuerCertUrl_Success() {
        // given
        final X509Certificate cert = X509UtilsWrapper.toX509(certificate);

        // when
        final String result = X509UtilsWrapper.getIssuerCertUrl(cert);

        // then
        Assertions.assertEquals(ISSUER_URL, result);
    }

    @Test
    void getIssuerCertUrl_Throws() {
        // given
        final X509Certificate cert = X509UtilsWrapper.toX509(certificate);

        // when-then
        try (var utils = mockStatic(AuthorityInformationAccessUtils.class)) {
            utils.when(() -> AuthorityInformationAccessUtils.getIssuerCertUrl(cert)).thenReturn(Optional.empty());
            Assertions.assertThrows(X509ParsingException.class, () -> X509UtilsWrapper.getIssuerCertUrl(cert));
        }
    }
}
