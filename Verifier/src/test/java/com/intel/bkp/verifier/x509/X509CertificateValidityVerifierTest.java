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

package com.intel.bkp.verifier.x509;

import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.exceptions.CertificateChainValidationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;

@ExtendWith(MockitoExtension.class)
class X509CertificateValidityVerifierTest {

    private static final String TEST_FOLDER = "certs/";

    // openssl req -newkey rsa:2048 -nodes -keyout CAkey.pem -x509 -days 365 -out CA.pem
    // openssl req -new -newkey rsa:2048 -nodes -keyout invalid.key -out invalid.csr
    // openssl x509 -req -days 0 -in invalid.csr -CA CA.pem -CAkey CAkey.pem -CAcreateserial -out invalid.pem -sha256
    private static final String INVALID_CERT = "invalid.pem";
    private static final String ROOT_CERT_FILENAME = "IPCS.cer";

    private static X509Certificate invalidCert;
    private static X509Certificate rootCert;

    private static final X509CertificateParser X509_PARSER = new X509CertificateParser();

    @InjectMocks
    private X509CertificateValidityVerifier sut;

    @BeforeAll
    static void init() throws Exception {
        invalidCert = X509_PARSER.toX509(Utils.readFromResources(TEST_FOLDER, INVALID_CERT));
        rootCert = X509_PARSER.toX509(Utils.readFromResources(TEST_FOLDER, ROOT_CERT_FILENAME));
    }

    @Test
    void verify_DoesNotThrow() {
        // when-then
        Assertions.assertDoesNotThrow(() -> sut.verify(rootCert));
    }

    @Test
    void verify_Throws() {
        // when-then
        Assertions.assertThrows(CertificateChainValidationException.class, () -> sut.verify(invalidCert));
    }
}
