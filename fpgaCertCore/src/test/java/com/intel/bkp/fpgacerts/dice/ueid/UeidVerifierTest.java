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

package com.intel.bkp.fpgacerts.dice.ueid;

import com.intel.bkp.fpgacerts.LogUtils;
import com.intel.bkp.fpgacerts.Utils;
import com.intel.bkp.fpgacerts.utils.DeviceIdUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.org.lidalia.slf4jext.Level;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_UEID;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UeidVerifierTest {

    private static final String TEST_FOLDER = "certs/dice/";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final byte[] DEVICE_ID = fromHex("06354FE4C1FF5E06");

    private static final byte[] VALID_UID = fromHex("0102030405060708");
    private static final String VALID_UEID_VALUE = "041430120410020007ED000034000102030405060708";
    private static final String VALID_SUBJECT = "CN=Intel:Agilex:L1:ski:0807060504030201";
    private static final String SUBJECT_WITH_DIFFERENT_FAMILY = "CN=Intel:Easic_n5x:L1:ski:0807060504030201";
    private static final String SUBJECT_WITH_UNKNOWN_FAMILY = "CN=Intel:Blabla:L1:ski:0807060504030201";
    private static final String SUBJECT_NOT_IN_EXPECTED_FORMAT = "CN=Intel:Agilex:blabla";
    private static final String DIFFERENT_UID = "1122334455667788";
    private static final String SUBJECT_WITH_DIFFERENT_DEVICE_ID =
        "CN=Intel:Agilex:L1:ski:" + DeviceIdUtil.getReversed(DIFFERENT_UID);

    private static X509Certificate certWithUeidExtension;
    private final UeidVerifier sut = new UeidVerifier();
    @Mock
    private X509Certificate certificate;

    @BeforeAll
    static void init() throws Exception {
        certWithUeidExtension = Utils.readCertificate(TEST_FOLDER, FIRMWARE_CERT);
    }

    @AfterEach
    void clearLogs() {
        LogUtils.clearLogs(sut.getClass());
    }

    @Test
    void verify_WithRealCert_ReturnsTrue() {
        // when
        final boolean valid = sut.certificates(List.of(certWithUeidExtension)).verify(DEVICE_ID);

        // then
        Assertions.assertTrue(valid);
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
        final String expectedErrorMessage = "Failed to parse UEID extension of certificate: " + VALID_SUBJECT;
        final byte[] invalidUeidValue = fromHex(VALID_UEID_VALUE + "010203");
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_UEID.getOid()));
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(invalidUeidValue);
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(VALID_SUBJECT));

        // when
        final boolean valid = sut.certificates(List.of(certificate)).verify(VALID_UID);

        // then
        Assertions.assertFalse(valid);
        Assertions.assertTrue(getErrorLogs().anyMatch(message -> message.contains(expectedErrorMessage)));
    }

    @Test
    void verify_WithOneCert_HasUnparsableSubjectFormat_ReturnsFalse() {
        // given
        final String expectedErrorMessage = "Failed to parse subject of certificate: " + SUBJECT_NOT_IN_EXPECTED_FORMAT;
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_UEID.getOid()));
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(VALID_UEID_VALUE));
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(SUBJECT_NOT_IN_EXPECTED_FORMAT));

        // when
        final boolean valid = sut.certificates(List.of(certificate)).verify(VALID_UID);

        // then
        Assertions.assertFalse(valid);
        Assertions.assertTrue(getErrorLogs().anyMatch(message -> message.contains(expectedErrorMessage)));
    }

    @Test
    void verify_WithOneCert_DoesNotContainMatchingUid_ReturnsFalse() {
        // given
        final byte[] mismatchedDeviceId = VALID_UID;
        final String expectedErrorMessage = String.format("Certificate has UEID extension with uid that does not match "
                + "deviceId: %s\nExpected: %s\nActual: %s",
            certWithUeidExtension.getSubjectX500Principal(), toHex(mismatchedDeviceId), toHex(DEVICE_ID));


        // when
        final boolean valid = sut.certificates(List.of(certWithUeidExtension)).verify(mismatchedDeviceId);

        // then
        Assertions.assertFalse(valid);
        Assertions.assertTrue(getErrorLogs().anyMatch(message -> message.contains(expectedErrorMessage)));
    }

    @Test
    void verify_WithOneCert_DoesNotContainMatchingUidInSubject_ReturnsFalse() {
        // given
        final String expectedErrorMessage = String.format(
            "Certificate has UEID extension with uid that does not match uid based on subject: %s"
                + "\nUid based on subject: %s\nUid in UEID extension: %s",
            SUBJECT_WITH_DIFFERENT_DEVICE_ID, DIFFERENT_UID, toHex(VALID_UID));
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_UEID.getOid()));
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(VALID_UEID_VALUE));
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(SUBJECT_WITH_DIFFERENT_DEVICE_ID));

        // when
        final boolean valid = sut.certificates(List.of(certificate)).verify(VALID_UID);

        // then
        Assertions.assertFalse(valid);
        Assertions.assertTrue(getErrorLogs().anyMatch(message -> message.contains(expectedErrorMessage)));
    }

    @Test
    void verify_WithOneCert_HasUnrecognizedFamilyNameInSubject_ReturnsFalse() {
        // given
        final String expectedErrorMessage =
            "Failed to recognize family name from subject of certificate: " + SUBJECT_WITH_UNKNOWN_FAMILY;
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_UEID.getOid()));
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(VALID_UEID_VALUE));
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(SUBJECT_WITH_UNKNOWN_FAMILY));

        // when
        final boolean valid = sut.certificates(List.of(certificate)).verify(VALID_UID);

        // then
        Assertions.assertFalse(valid);
        Assertions.assertTrue(getErrorLogs().anyMatch(message -> message.contains(expectedErrorMessage)));
    }

    @Test
    void verify_WithOneCert_DoesNotContainMatchingFamily_ReturnsFalse() {
        // given
        final String expectedErrorMessage = String.format("Certificate has UEID extension with familyId that does not "
                + "match family based on subject: %s\nExpected: 0x35 (easic_n5x)\nActual: 0x34 (agilex)",
            SUBJECT_WITH_DIFFERENT_FAMILY);
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_UEID.getOid()));
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(VALID_UEID_VALUE));
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(SUBJECT_WITH_DIFFERENT_FAMILY));

        // when
        final boolean valid = sut.certificates(List.of(certificate)).verify(VALID_UID);

        // then
        Assertions.assertFalse(valid);
        Assertions.assertTrue(getErrorLogs().anyMatch(message -> message.contains(expectedErrorMessage)));
    }

    @Test
    void verify_WithOneCert_ContainsMatchingUidAndFamily_ReturnsTrue() {
        // given
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_UEID.getOid()));
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(VALID_UEID_VALUE));
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(VALID_SUBJECT));

        // when
        final boolean valid = sut.certificates(List.of(certificate)).verify(VALID_UID);

        // then
        Assertions.assertTrue(valid);
    }

    @Test
    void verify_WithMultipleCerts_OneCertDoesNotContainMatchingUid_ReturnsFalse() {
        // given
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_UEID.getOid()));
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(VALID_UEID_VALUE));
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(VALID_SUBJECT));

        // when
        final boolean valid = sut.certificates(List.of(certificate, certWithUeidExtension)).verify(DEVICE_ID);

        // then
        Assertions.assertFalse(valid);
    }

    @Test
    void verify_WithMultipleCerts_AllCertsContainMatchingUidAndFamilyOrNoExtension_ReturnsTrue() {
        // given
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of());
        when(certificate.getNonCriticalExtensionOIDs()).thenReturn(Set.of());

        // when
        final boolean valid = sut.certificates(List.of(certificate, certWithUeidExtension)).verify(DEVICE_ID);

        // then
        Assertions.assertTrue(valid);
    }

    private Stream<String> getErrorLogs() {
        return LogUtils.getLogs(sut.getClass(), Level.ERROR);
    }
}
