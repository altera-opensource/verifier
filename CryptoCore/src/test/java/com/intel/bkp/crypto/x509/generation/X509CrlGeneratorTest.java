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

package com.intel.bkp.crypto.x509.generation;

import com.intel.bkp.test.CertificateUtils;
import com.intel.bkp.test.KeyGenUtils;
import lombok.SneakyThrows;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.Provider;
import java.security.cert.X509CRL;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class X509CrlGeneratorTest {

    private static final Provider PROVIDER = new BouncyCastleProvider();
    private static final BigInteger CRL_NUMBER = BigInteger.ZERO;

    @Test
    void generateCrl_Success() throws Exception {
        // given
        final ICrlParams crlParams = prepareCrlParams();

        // when
        final X509CRL crl = X509CrlGenerator.generateCrl(crlParams);

        // then
        assertNotNull(crl);
    }

    @SneakyThrows
    private ICrlParams prepareCrlParams() {
        final var signingKeyPair = KeyGenUtils.genEc384();
        final var signingCert = CertificateUtils.generateCertificate(signingKeyPair);
        final var issuerDTO = new X509CrlIssuerDTO(signingCert, signingKeyPair.getPrivate(), PROVIDER);

        final var crlParams = mock(ICrlParams.class);
        when(crlParams.getIssuer()).thenReturn(issuerDTO);
        when(crlParams.getCrlNumber()).thenReturn(CRL_NUMBER);
        when(crlParams.getNextUpdate(any())).thenReturn(DateUtils.addDays(new Date(), 1));
        return crlParams;
    }

}
