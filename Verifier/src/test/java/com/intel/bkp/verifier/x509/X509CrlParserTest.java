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

import com.intel.bkp.ext.core.crl.CrlSerialNumberBuilder;
import com.intel.bkp.verifier.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.List;
import java.util.stream.Collectors;

@ExtendWith(MockitoExtension.class)
class X509CrlParserTest {

    private static final String TEST_FOLDER = "certs/";

    // https://tsci.intel.com/content/IPCS/crls/IPCSSigningCA.crl
    private static final String PEM_CRL_FILENAME = "IPCSSigningCA.crl";
    private static final String PEM_CERT_SUBJECT = "CN=IPCS Signing Cert Test,OU=Intel PUF Certificate Service," +
        "O=Intel Corporation,L=Santa Clara,ST=CA,C=US";
    private static final String DEVICE_ID_REVOKED = "8062002DB6189C87";

    // https://tsci.intel.com/content/DICE/crls/DICE.crl
    private static final String DER_CRL_FILENAME = "DICE.crl";
    private static final String DER_CERT_SUBJECT = "CN=Intel DICE Root CA";

    private static byte[] crlPemEncoded;
    private static byte[] crlDerEncoded;

    private X509CrlParser sut = new X509CrlParser();

    @BeforeAll
    static void init() throws Exception {
        crlPemEncoded = Utils.readFromResources(TEST_FOLDER, PEM_CRL_FILENAME);
        crlDerEncoded = Utils.readFromResources(TEST_FOLDER, DER_CRL_FILENAME);
    }

    @Test
    void toX509_DerCrl_Success() {
        // when
        final X509CRL result = sut.toX509(crlDerEncoded);

        // then
        Assertions.assertEquals(DER_CERT_SUBJECT, result.getIssuerX500Principal().getName());
    }

    @Test
    void toX509_PemCrl_Success() {
        // when
        final X509CRL result = sut.toX509(crlPemEncoded);

        // then
        Assertions.assertEquals(PEM_CERT_SUBJECT, result.getIssuerX500Principal().getName());
    }

    @Test
    void toX509_ReturnsRevokedDevice() {
        // given
        final BigInteger oneOfTheRevokedDevices = CrlSerialNumberBuilder.convertToBigInteger(DEVICE_ID_REVOKED);
        final int totalNumOfRevokedDevices = 37;

        // when
        final X509CRL result = sut.toX509(crlPemEncoded);

        // then
        final List<BigInteger> revokedDevices = getRevokedDevice(result);
        Assertions.assertEquals(totalNumOfRevokedDevices, revokedDevices.size());
        Assertions.assertTrue(revokedDevices.contains(oneOfTheRevokedDevices));
    }

    private List<BigInteger> getRevokedDevice(X509CRL crl) {
        return crl
            .getRevokedCertificates()
            .stream()
            .map(X509CRLEntry::getSerialNumber)
            .collect(Collectors.toUnmodifiableList());
    }
}
