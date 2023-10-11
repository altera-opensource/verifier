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
import com.intel.bkp.test.enumeration.ResourceDir;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.pemToX509Certificate;
import static com.intel.bkp.utils.ListUtils.toLinkedList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class X509CertificateUtilsTest {

    private static final String CERT_PEM_FILE = "cert_withoutAKIandSKI.pem";

    private static String certInPem;
    private final X500Principal issuer = new X500Principal("CN=ISSUER");
    private final X500Principal subject = new X500Principal("CN=SUBJECT");

    @Mock
    private X509Certificate selfSignedCert;
    @Mock
    private X509Certificate leafCert;

    @Mock
    private X509Certificate certificate;
    @Mock
    private PublicKey publicKey;

    @BeforeAll
    static void init() {
        certInPem = FileUtils.loadFile(ResourceDir.CERTS, CERT_PEM_FILE);
    }

    @Test
    void toPem_Success() throws Exception {
        // when
        final String result = X509CertificateUtils.toPem(pemToX509Certificate(certInPem));

        // then
        assertEquals(certInPem, result);
    }

    @Test
    void isSelfSigned_DifferentIssuerAndSubject_ReturnsFalse() {
        // given
        when(certificate.getIssuerX500Principal()).thenReturn(issuer);
        when(certificate.getSubjectX500Principal()).thenReturn(subject);

        // when
        final boolean result = X509CertificateUtils.isSelfSigned(certificate);

        // then
        assertFalse(result);
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
        assertFalse(result);
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
        assertTrue(result);
    }

    @Test
    void makeRootLastCert_EmptyList_ReturnsEmptyList() {
        // given
        final List<X509Certificate> result = X509CertificateUtils.makeRootLastCert(List.of());

        // then
        assertEquals(0, result.size());
    }

    @Test
    void makeRootLastCert_NoRootPresent_ReturnsEmptyList() {
        // given
        final LinkedList<X509Certificate> certs = toLinkedList(List.of(leafCert, selfSignedCert));

        try (var x509CertUtilsMockedStatic = mockStatic(X509CertificateUtils.class, CALLS_REAL_METHODS)) {
            mockSelfSigned(x509CertUtilsMockedStatic, leafCert, false);
            mockSelfSigned(x509CertUtilsMockedStatic, selfSignedCert, false);

            // when
            final LinkedList<X509Certificate> result = toLinkedList(X509CertificateUtils.makeRootLastCert(certs));

            // then
            assertEquals(0, result.size());
        }
    }

    @Test
    void makeRootLastCert_RootLast_DoesNothing() {
        // given
        final LinkedList<X509Certificate> certs = toLinkedList(List.of(leafCert, selfSignedCert));

        try (var x509CertUtilsMockedStatic = mockStatic(X509CertificateUtils.class, CALLS_REAL_METHODS)) {
            mockSelfSigned(x509CertUtilsMockedStatic, leafCert, false);
            mockSelfSigned(x509CertUtilsMockedStatic, selfSignedCert, true);

            // when
            final LinkedList<X509Certificate> result = toLinkedList(X509CertificateUtils.makeRootLastCert(certs));

            // then
            assertCertsInOrder(result);
        }
    }

    @Test
    void makeRootLastCert_RootFirst_Reverses() {
        // given
        final LinkedList<X509Certificate> certs = toLinkedList(List.of(selfSignedCert, leafCert));

        try (var x509CertUtilsMockedStatic = mockStatic(X509CertificateUtils.class, CALLS_REAL_METHODS)) {
            mockSelfSigned(x509CertUtilsMockedStatic, leafCert, false);
            mockSelfSigned(x509CertUtilsMockedStatic, selfSignedCert, true);

            // when
            final LinkedList<X509Certificate> result = toLinkedList(X509CertificateUtils.makeRootLastCert(certs));

            // then
            assertCertsInOrder(result);
        }
    }

    private void mockSelfSigned(MockedStatic<X509CertificateUtils> x509CertUtilsMockedStatic,
                                X509Certificate cert, boolean value) {
        x509CertUtilsMockedStatic
            .when(() -> X509CertificateUtils.isSelfSigned(cert))
            .thenReturn(value);
    }

    private void assertCertsInOrder(LinkedList<X509Certificate> result) {
        assertEquals(leafCert, result.getFirst());
        assertEquals(selfSignedCert, result.getLast());
    }
}
