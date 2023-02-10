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

package com.intel.bkp.fpgacerts.dice.subject;

import ch.qos.logback.classic.Level;
import com.intel.bkp.fpgacerts.LoggerTestUtil;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_UEID;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiceSubjectVerifierTest {

    private LoggerTestUtil loggerTestUtil;

    private static final String VALID_COMPANY = "Intel";
    private static final String VALID_FAMILY = "Agilex";
    private static final String DIFFERENT_VALID_FAMILY = "Easic_n5x";
    private static final String DEVICE_ID = "0102030405060708";
    private static final String DIFFERENT_DEVICE_ID = "0123456789abcdef";
    private final DiceSubjectVerifier sut = new DiceSubjectVerifier();
    @Mock
    private X509Certificate child;
    @Mock
    private X509Certificate parent;
    @Mock
    private X509Certificate root;

    @BeforeEach
    void setup() {
        loggerTestUtil = LoggerTestUtil.instance(sut.getClass());
    }

    @Test
    void verify_ReturnsTrue() {
        // given
        final var chain = List.of(child, parent, root);
        mockUeidExtensionExists(child);
        mockUeidExtensionExists(parent);
        mockUeidExtensionExists(root);
        mockSubject(generateSubjectWithDefaults(), child);
        mockSubject(generateSubjectWithDefaults(), parent);
        mockSubject(generateSubjectWithDefaults(), root);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_EmptyCertificatesList_ReturnsFalse() {
        // when
        final boolean result = sut.certificates(List.of()).verify();

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void verify_NoUeidInAllCerts_ReturnsTrue() {
        // given
        final var chain = List.of(child, parent, root);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_NoUeidInOneCert_ReturnsTrue() {
        // given
        final var chain = List.of(child, parent, root);
        mockUeidExtensionExists(child);
        mockUeidExtensionExists(parent);
        mockSubject(generateSubjectWithDefaults(), child);
        mockSubject(generateSubjectWithDefaults(), parent);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_UeidInOneCertOnly_ReturnsTrue() {
        // given
        final var chain = List.of(child, parent, root);
        mockUeidExtensionExists(child);
        mockSubject(generateSubjectWithDefaults(), child);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void verify_InvalidSubjectFormat_ReturnsFalse() {
        // given
        final String expectedError =
            "One of certificates that contain UEID extension has invalid subject, that could not be parsed.";
        final var chain = List.of(child, parent, root);
        mockUeidExtensionExists(child);
        mockSubject("CN=Intel:Agilex", child);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertFalse(result);
        Assertions.assertTrue(loggerTestUtil.contains(expectedError, Level.ERROR));
    }

    @Test
    void verify_InconsistentCompany_ReturnsFalse() {
        // given
        final String differentCompany = "some company";
        final String expectedError =
            String.format("Inconsistent subject component - all certificates in chain should have the same value."
                + "\nDistinct values in chain: %s, %s", VALID_COMPANY, differentCompany);
        final var chain = List.of(child, parent, root);
        mockUeidExtensionExists(child);
        mockUeidExtensionExists(parent);
        mockUeidExtensionExists(root);
        mockSubject(generateSubjectWithDefaults(), child);
        mockSubject(generateSubjectWithDifferentCompany(differentCompany), parent);
        mockSubject(generateSubjectWithDefaults(), root);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertFalse(result);
        Assertions.assertTrue(loggerTestUtil.contains(expectedError, Level.ERROR));
    }

    @Test
    void verify_InconsistentFamily_ReturnsFalse() {
        // given
        final String expectedError =
            String.format("Inconsistent subject component - all certificates in chain should have the same value."
                + "\nDistinct values in chain: %s, %s", DIFFERENT_VALID_FAMILY, VALID_FAMILY);
        final var chain = List.of(child, parent, root);
        mockUeidExtensionExists(child);
        mockUeidExtensionExists(parent);
        mockUeidExtensionExists(root);
        mockSubject(generateSubjectWithDifferentFamilyName(DIFFERENT_VALID_FAMILY), child);
        mockSubject(generateSubjectWithDefaults(), parent);
        mockSubject(generateSubjectWithDefaults(), root);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertFalse(result);
        Assertions.assertTrue(loggerTestUtil.contains(expectedError, Level.ERROR));
    }

    @Test
    void verify_InconsistentDeviceId_ReturnsFalse() {
        // given
        final String expectedError =
            String.format("Inconsistent subject component - all certificates in chain should have the same value."
                + "\nDistinct values in chain: %s, %s", DIFFERENT_DEVICE_ID, DEVICE_ID);
        final var chain = List.of(child, parent, root);
        mockUeidExtensionExists(child);
        mockUeidExtensionExists(parent);
        mockUeidExtensionExists(root);
        mockSubject(generateSubjectWithDifferentDeviceId(), child);
        mockSubject(generateSubjectWithDefaults(), parent);
        mockSubject(generateSubjectWithDefaults(), root);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertFalse(result);
        Assertions.assertTrue(loggerTestUtil.contains(expectedError, Level.ERROR));
    }

    @Test
    void verify_InvalidCompany_ReturnsFalse() {
        // given
        final String companyInUppercase = VALID_COMPANY.toUpperCase();
        final String expectedError =
            String.format("Company name in certificate subject is incorrect.\nExpected: %s\nActual: %s",
                VALID_COMPANY, companyInUppercase);
        final var chain = List.of(child, parent, root);
        mockUeidExtensionExists(child);
        mockUeidExtensionExists(parent);
        mockUeidExtensionExists(root);
        mockSubject(generateSubjectWithDifferentCompany(companyInUppercase), child);
        mockSubject(generateSubjectWithDifferentCompany(companyInUppercase), parent);
        mockSubject(generateSubjectWithDifferentCompany(companyInUppercase), root);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertFalse(result);
        Assertions.assertTrue(loggerTestUtil.contains(expectedError, Level.ERROR));
    }

    @Test
    void verify_UnknownFamilyName_ReturnsFalse() {
        // given
        final String unknownFamilyName = "someFamily";
        final String expectedError = "Unknown family name in certificate subject in chain: " + unknownFamilyName;
        final var chain = List.of(child, parent, root);
        mockUeidExtensionExists(child);
        mockUeidExtensionExists(parent);
        mockUeidExtensionExists(root);
        mockSubject(generateSubjectWithDifferentFamilyName(unknownFamilyName), child);
        mockSubject(generateSubjectWithDifferentFamilyName(unknownFamilyName), parent);
        mockSubject(generateSubjectWithDifferentFamilyName(unknownFamilyName), root);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertFalse(result);
        Assertions.assertTrue(loggerTestUtil.contains(expectedError, Level.ERROR));
    }

    @Test
    void verify_NotCapitalizedFamilyName_ReturnsFalse() {
        // given
        final String lowercaseFamilyName = VALID_FAMILY.toLowerCase(Locale.ROOT);
        final String expectedError = String.format("Family name has incorrect letter size.\nExpected: %s\nActual: %s",
            VALID_FAMILY, lowercaseFamilyName);
        final var chain = List.of(child, parent, root);
        mockUeidExtensionExists(child);
        mockUeidExtensionExists(parent);
        mockUeidExtensionExists(root);
        mockSubject(generateSubjectWithDifferentFamilyName(lowercaseFamilyName), child);
        mockSubject(generateSubjectWithDifferentFamilyName(lowercaseFamilyName), parent);
        mockSubject(generateSubjectWithDifferentFamilyName(lowercaseFamilyName), root);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        Assertions.assertFalse(result);
        Assertions.assertTrue(loggerTestUtil.contains(expectedError, Level.ERROR));
    }

    private String generateSubjectWithDefaults() {
        return generateSubject(VALID_COMPANY, VALID_FAMILY, DEVICE_ID);
    }

    private String generateSubjectWithDifferentCompany(String company) {
        return generateSubject(company, VALID_FAMILY, DEVICE_ID);
    }

    private String generateSubjectWithDifferentFamilyName(String familyName) {
        return generateSubject(VALID_COMPANY, familyName, DEVICE_ID);
    }

    private String generateSubjectWithDifferentDeviceId() {
        return generateSubject(VALID_COMPANY, VALID_FAMILY, DIFFERENT_DEVICE_ID);
    }

    private String generateSubject(String company, String familyName, String deviceId) {
        final String level = RandomStringUtils.randomAlphanumeric(2);
        final String additionalData = RandomStringUtils.randomAlphanumeric(16);
        return String.format("CN=%s:%s:%s:%s:%s", company, familyName, level, additionalData, deviceId);
    }

    private void mockSubject(String subject, X509Certificate certificate) {
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(subject));
    }

    private void mockUeidExtensionExists(X509Certificate certificate) {
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_UEID.getOid()));
    }
}
