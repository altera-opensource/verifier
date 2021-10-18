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

package com.intel.bkp.verifier.service.certificate;

import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RootHashVerifierTest {

    private static final byte[] CERT_ENCODED = new byte[] { 1, 2 };
    private static final String VALID_HASH = DigestUtils.sha256Hex(CERT_ENCODED);
    private static final String INVALID_HASH = "INVALID";

    @Mock
    private X509Certificate certificate;

    private final RootHashVerifier sut = new RootHashVerifier();

    @Test
    void verifyRootHash_WithBlankHash_Skip() {
        // when
        final boolean result = sut.verifyRootHash(certificate, "");

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verifyRootHash_WithMatchingHash_ReturnsTrue() throws CertificateEncodingException {
        // given
        when(certificate.getEncoded()).thenReturn(CERT_ENCODED);

        // when
        final boolean result = sut.verifyRootHash(certificate, VALID_HASH);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verifyRootHash_WithNotMatchingHash_ReturnsFalse() throws CertificateEncodingException {
        // given
        when(certificate.getEncoded()).thenReturn(CERT_ENCODED);

        // when
        final boolean result = sut.verifyRootHash(certificate, INVALID_HASH);

        // then
        Assertions.assertFalse(result);
    }
}
