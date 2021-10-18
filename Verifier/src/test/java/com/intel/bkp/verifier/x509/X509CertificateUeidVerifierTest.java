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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static com.intel.bkp.ext.utils.HexConverter.fromHex;
import static com.intel.bkp.verifier.Utils.readFromResources;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_UEID;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class X509CertificateUeidVerifierTest {

    private static final String TEST_FOLDER = "responses/";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final byte[] DEVICE_ID = fromHex("06354FE4C1FF5E06");
    private static final X509CertificateParser X509_PARSER = new X509CertificateParser();

    private static final byte[] VALID_UID = fromHex("0102030405060708");
    private static final String VALID_UEID_VALUE = "041430120410020007ED000034000102030405060708";

    private static X509Certificate certWithUeidExtension;

    @Mock
    private X509Certificate certificate;

    private final X509CertificateUeidVerifier sut = new X509CertificateUeidVerifier();

    @BeforeAll
    static void init() throws Exception {
        certWithUeidExtension = X509_PARSER.toX509(readFromResources(TEST_FOLDER, FIRMWARE_CERT));
    }

    @Test
    void verify_WithOneCert_DoesNotContainUeidExtension_ReturnsTrue() {
        // given
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of());
        when(certificate.getNonCriticalExtensionOIDs()).thenReturn(Set.of());

        // when
        final boolean valid = sut.certificates(List.of(certificate)).verify(DEVICE_ID);

        // then
        Assertions.assertTrue(valid);
    }

    @Test
    void verify_WithOneCert_ContainsInvalidUeidExtension_ReturnsFalse() {
        // given
        final byte[] invalidUeidValue = fromHex(VALID_UEID_VALUE + "010203");
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_UEID.getOid()));
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(invalidUeidValue);

        // when
        final boolean valid = sut.certificates(List.of(certificate)).verify(VALID_UID);

        // then
        Assertions.assertFalse(valid);
    }

    @Test
    void verify_WithOneCert_ContainsMatchingUid_ReturnsTrue() {
        // when
        final boolean valid = sut.certificates(List.of(certWithUeidExtension)).verify(DEVICE_ID);

        // then
        Assertions.assertTrue(valid);
    }

    @Test
    void verify_WithOneCert_DoesNotContainMatchingUid_ReturnsFalse() {
        // given
        final byte[] mismatchedDeviceId = VALID_UID;

        // when
        final boolean valid = sut.certificates(List.of(certWithUeidExtension)).verify(mismatchedDeviceId);

        // then
        Assertions.assertFalse(valid);
    }

    @Test
    void verify_WithMultipleCerts_OneCertDoesNotContainMatchingUid_ReturnsFalse() {
        // given
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_UEID.getOid()));
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(VALID_UEID_VALUE));

        // when
        final boolean valid = sut.certificates(List.of(certificate, certWithUeidExtension)).verify(DEVICE_ID);

        // then
        Assertions.assertFalse(valid);
    }

    @Test
    void verify_WithMultipleCerts_AllCertsContainMatchingUidOrNoExtension_ReturnsTrue() {
        // given
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of());
        when(certificate.getNonCriticalExtensionOIDs()).thenReturn(Set.of());

        // when
        final boolean valid = sut.certificates(List.of(certificate, certWithUeidExtension)).verify(DEVICE_ID);

        // then
        Assertions.assertTrue(valid);
    }

}
