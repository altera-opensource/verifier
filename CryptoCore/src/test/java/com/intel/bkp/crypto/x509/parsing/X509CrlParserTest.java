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

package com.intel.bkp.crypto.x509.parsing;

import com.intel.bkp.crypto.TestUtil;
import com.intel.bkp.crypto.exceptions.X509CrlParsingException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.intel.bkp.utils.HexConverter.fromHex;

class X509CrlParserTest {

    private static final String TEST_FOLDER = "/certs/";

    // https://tsci.intel.com/content/IPCS/crls/IPCSSigningCA.crl
    private static final String PEM_CRL_FILENAME = "IPCSSigningCA.crl";
    private static final String PEM_CERT_SUBJECT = "CN=IPCS Signing Cert Test,OU=Intel PUF Certificate Service," +
        "O=Intel Corporation,L=Santa Clara,ST=CA,C=US";
    private static final String DEVICE_ID_REVOKED = "8062002DB6189C87";

    // https://tsci.intel.com/content/DICE/crls/DICE.crl
    private static final String DER_CRL_FILENAME = "DICE.crl";
    private static final String DER_CERT_SUBJECT = "CN=Intel DICE Root CA";

    private static final byte[] WRONG_DATA_ARG = new byte[]{0x01, 0x02};

    private static String crlPemString;
    private static byte[] crlPemEncoded;
    private static byte[] crlDerEncoded;

    @BeforeAll
    static void init() throws Exception {
        crlPemString = TestUtil.getResourceAsString(TEST_FOLDER, PEM_CRL_FILENAME);
        crlPemEncoded = TestUtil.getResourceAsBytes(TEST_FOLDER, PEM_CRL_FILENAME);
        crlDerEncoded = TestUtil.getResourceAsBytes(TEST_FOLDER, DER_CRL_FILENAME);
    }

    @Test
    void pemToX509Crl_PemCrl_Success() throws X509CrlParsingException {
        // when
        final X509CRL result = X509CrlParser.pemToX509Crl(crlPemString);

        // then
        Assertions.assertEquals(PEM_CERT_SUBJECT, result.getIssuerX500Principal().getName());
    }

    @Test
    void pemToX509Crl_EmptyString_Throws() {
        // when-then
        Assertions.assertThrows(X509CrlParsingException.class, () -> X509CrlParser.pemToX509Crl(""));
    }

    @Test
    void pemToX509Crl_InvalidInput_Throws() {
        // when-then
        Assertions.assertThrows(X509CrlParsingException.class, () -> X509CrlParser.pemToX509Crl("not a crl in pem"));
    }

    @Test
    void toX509Crl_PemCrl_Success() throws X509CrlParsingException {
        // when
        final X509CRL result = X509CrlParser.toX509Crl(crlPemEncoded);

        // then
        Assertions.assertEquals(PEM_CERT_SUBJECT, result.getIssuerX500Principal().getName());
    }

    @Test
    void toX509Crl_DerCrl_Success() throws X509CrlParsingException {
        // when
        final X509CRL result = X509CrlParser.toX509Crl(crlDerEncoded);

        // then
        Assertions.assertEquals(DER_CERT_SUBJECT, result.getIssuerX500Principal().getName());
    }

    @Test
    void toX509Crl_InvalidInput_Throws() {
        // when-then
        Assertions.assertThrows(X509CrlParsingException.class, () -> X509CrlParser.toX509Crl(WRONG_DATA_ARG));
    }

    @Test
    void toX509Crl_ReturnsRevokedDevice() throws X509CrlParsingException {
        // given
        final BigInteger oneOfTheRevokedDevices = convertDeviceIdToSerialNumber(DEVICE_ID_REVOKED);
        final int totalNumOfRevokedDevices = 37;

        // when
        final X509CRL result = X509CrlParser.toX509Crl(crlPemEncoded);

        // then
        final List<BigInteger> revokedDevices = getRevokedDevice(result);
        Assertions.assertEquals(totalNumOfRevokedDevices, revokedDevices.size());
        Assertions.assertTrue(revokedDevices.contains(oneOfTheRevokedDevices));
    }

    @Test
    void tryToX509_DerCrl_ReturnsTrue() {
        // when
        final Optional<X509CRL> result = X509CrlParser.tryToX509(crlDerEncoded);

        // then
        Assertions.assertTrue(result.isPresent());
    }

    @Test
    void tryToX509_InvalidInput_ReturnsFalse() {

        // when
        final Optional<X509CRL> result = X509CrlParser.tryToX509(WRONG_DATA_ARG);

        // then
        Assertions.assertFalse(result.isPresent());
    }

    private BigInteger convertDeviceIdToSerialNumber(String deviceId) {
        return new BigInteger(fromHex("01" + deviceId));
    }

    private List<BigInteger> getRevokedDevice(X509CRL crl) {
        return crl
            .getRevokedCertificates()
            .stream()
            .map(X509CRLEntry::getSerialNumber)
            .collect(Collectors.toUnmodifiableList());
    }

}
