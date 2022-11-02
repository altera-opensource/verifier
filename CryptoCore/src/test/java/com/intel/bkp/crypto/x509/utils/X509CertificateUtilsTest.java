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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.pemToX509Certificate;
import static org.bouncycastle.asn1.x509.Extension.basicConstraints;
import static org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class X509CertificateUtilsTest {

    /* Below certs were generated using OpenSSL with command:
        openssl req -newkey rsa:2048 -nodes -keyout test.pem -x509 -days 365 -out cert.pem
        The fact if cert contains AKI and SKI extensions depends on content of openssl.cnf
        Value of KEY_IDENTIFIER is equal to both AKI and SKI (cert is self-signed) and is taken from output of command:
        openssl x509 --text -in cert.pem
     */
    private static final String CERT_WITHOUT_AKI_AND_SKI = "cert_withoutAKIandSKI.pem";

    private static String certInPem;
    private static X509Certificate certWithoutAKIandSKI;
    private final X500Principal issuer = new X500Principal("CN=ISSUER");
    private final X500Principal subject = new X500Principal("CN=SUBJECT");

    @Mock
    private X509Certificate certificate;
    @Mock
    private PublicKey publicKey;

    @BeforeAll
    static void init() throws Exception {
        certInPem = TestUtil.getResourceAsString("/certs/", CERT_WITHOUT_AKI_AND_SKI);
        certWithoutAKIandSKI = pemToX509Certificate(certInPem);
    }

    @Test
    void toPem_Success() throws Exception {
        // when
        final String result = X509CertificateUtils.toPem(certWithoutAKIandSKI);

        // then
        Assertions.assertEquals(certInPem, result);
    }

    @Test
    void isSelfSigned_DifferentIssuerAndSubject_ReturnsFalse() {
        // given
        when(certificate.getIssuerX500Principal()).thenReturn(issuer);
        when(certificate.getSubjectX500Principal()).thenReturn(subject);

        // when
        final boolean result = X509CertificateUtils.isSelfSigned(certificate);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void isSelfSigned_SameIssuerAndSubjectButFailedSignature_ReturnsFalse() throws CertificateException,
        NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        // given
        when(certificate.getIssuerX500Principal()).thenReturn(issuer);
        when(certificate.getSubjectX500Principal()).thenReturn(issuer);
        when(certificate.getPublicKey()).thenReturn(publicKey);
        doThrow(CertificateException.class).when(certificate).verify(publicKey);

        // when
        final boolean result = X509CertificateUtils.isSelfSigned(certificate);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void isSelfSigned_ReturnsTrue() {
        // given
        when(certificate.getIssuerX500Principal()).thenReturn(issuer);
        when(certificate.getSubjectX500Principal()).thenReturn(issuer);
        when(certificate.getPublicKey()).thenReturn(publicKey);

        // when
        final boolean result = X509CertificateUtils.isSelfSigned(certificate);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void containsExtension_ExtensionIsCritical_ReturnsTrue() {
        // given
        final ASN1ObjectIdentifier oid = basicConstraints;
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(oid.getId()));

        // when
        final boolean result = X509CertificateUtils.containsExtension(certificate, oid);

        // then
        Assertions.assertTrue(result);

    }

    @Test
    void containsExtension_ExtensionIsNonCritical_ReturnsTrue() {
        // given
        final ASN1ObjectIdentifier oid = basicConstraints;
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of());
        when(certificate.getNonCriticalExtensionOIDs()).thenReturn(Set.of(oid.getId()));

        // when
        final boolean result = X509CertificateUtils.containsExtension(certificate, oid);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void containsExtension_ExtensionDoesNotExist_ReturnsFalse() {
        // when
        final boolean result = X509CertificateUtils.containsExtension(certWithoutAKIandSKI, subjectKeyIdentifier);

        // then
        Assertions.assertFalse(result);
    }
}
