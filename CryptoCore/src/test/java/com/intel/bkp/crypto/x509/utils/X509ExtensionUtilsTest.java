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

import com.intel.bkp.crypto.TestUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.Set;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.pemToX509Certificate;
import static com.intel.bkp.crypto.x509.parsing.X509CrlParser.pemToX509Crl;
import static com.intel.bkp.crypto.x509.utils.X509CrlUtils.getX509CRLEntries;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class X509ExtensionUtilsTest {

    /* Below cert were generated using OpenSSL with command:
        openssl req -newkey rsa:2048 -nodes -keyout test.pem -x509 -days 365 -out cert.pem
        The fact if cert contains AKI and SKI extensions depends on content of openssl.cnf
        Value of KEY_IDENTIFIER is equal to both AKI and SKI (cert is self-signed) and is taken from output of command:
        openssl x509 --text -in cert.pem
    */
    private static final String CERT_WITHOUT_AKI_AND_SKI = "cert_withoutAKIandSKI.pem";
    private static final String CRL_WITH_REVOKED_SN = "IPCS_agilex.crl";

    private static X509Certificate certWithoutAKIandSKI;
    private static X509CRL crl;

    @Mock
    private X509Certificate certificate;

    @BeforeAll
    static void init() throws Exception {
        final String certInPem = TestUtil.getResourceAsString("/certs/", CERT_WITHOUT_AKI_AND_SKI);
        certWithoutAKIandSKI = pemToX509Certificate(certInPem);

        final String crlInPem = TestUtil.getResourceAsString("/certs/", CRL_WITH_REVOKED_SN);
        crl = pemToX509Crl(crlInPem);
    }

    @Test
    void containsExtension_ExtensionIsCritical_ReturnsTrue() {
        // given
        final ASN1ObjectIdentifier oid = Extension.basicConstraints;
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(oid.getId()));

        // when
        final boolean result = X509ExtensionUtils.containsExtension(certificate, oid);

        // then
        Assertions.assertTrue(result);

    }

    @Test
    void containsExtension_ExtensionIsNonCritical_ReturnsTrue() {
        // given
        final ASN1ObjectIdentifier oid = Extension.basicConstraints;
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of());
        when(certificate.getNonCriticalExtensionOIDs()).thenReturn(Set.of(oid.getId()));

        // when
        final boolean result = X509ExtensionUtils.containsExtension(certificate, oid);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void containsExtension_ExtensionDoesNotExist_ReturnsFalse() {
        // when
        final boolean result =
            X509ExtensionUtils.containsExtension(certWithoutAKIandSKI, Extension.subjectKeyIdentifier);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void getExtensionBytes_ExtensionExists_ReturnsBytes() {
        // given
        // extracted from CRL using ASN.1 Editor
        final byte[] extensionBytes = fromHex("30168014B80FCD57D30A9D017AC82AEC8D1EF00DA9D424B0");

        // when
        final var result = X509ExtensionUtils.getExtensionBytes(crl, Extension.authorityKeyIdentifier);

        // then
        Assertions.assertTrue(result.isPresent());
        Assertions.assertArrayEquals(extensionBytes, result.get());
    }

    @Test
    void getExtensionBytes_ExtensionDoesNotExist_ReturnsEmptyOptional() {
        // when
        final var result = X509ExtensionUtils.getExtensionBytes(crl, Extension.subjectKeyIdentifier);

        // then
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void getObjDescription_withCertificate_Success() {
        // given
        final String expectedDescription = "certificate: O=Internet Widgits Pty Ltd, ST=Some-State, C=AU";

        // when-then
        getObjDescription_ReturnsExpectedDescription(expectedDescription, certWithoutAKIandSKI);
    }

    @Test
    void getObjDescription_withCrl_Success() {
        // given
        final String expectedDescription = "CRL issued by: CN=Intel:Agilex:IPCS";

        // when-then
        getObjDescription_ReturnsExpectedDescription(expectedDescription, crl);
    }

    @Test
    void getObjDescription_withCrlEntry_Success() {
        // given
        final X509CRLEntry crlEntry = getX509CRLEntries(crl).findFirst().get();
        final String expectedDescription = "CRL entry with serial number: 0128000102030405060708090A0B0C0D0E0FFFF1";

        // when-then
        getObjDescription_ReturnsExpectedDescription(expectedDescription, crlEntry);
    }

    @Test
    void getObjDescription_withCustomClass_Success() {
        // given
        final var customObj = new CustomX509ExtensionsObject();
        final String expectedDescription = "object: some custom string representation";

        // when-then
        getObjDescription_ReturnsExpectedDescription(expectedDescription, customObj);
    }

    private void getObjDescription_ReturnsExpectedDescription(String expectedDescription, X509Extension x509Obj) {
        // when
        final String description = X509ExtensionUtils.getObjDescription(x509Obj);

        // then
        Assertions.assertEquals(expectedDescription, description);
    }

    private static class CustomX509ExtensionsObject implements X509Extension {

        @Override
        public String toString() {
            return "some custom string representation";
        }

        @Override
        public boolean hasUnsupportedCriticalExtension() {
            return false;
        }

        @Override
        public Set<String> getCriticalExtensionOIDs() {
            return null;
        }

        @Override
        public Set<String> getNonCriticalExtensionOIDs() {
            return null;
        }

        @Override
        public byte[] getExtensionValue(String oid) {
            return new byte[0];
        }
    }
}
