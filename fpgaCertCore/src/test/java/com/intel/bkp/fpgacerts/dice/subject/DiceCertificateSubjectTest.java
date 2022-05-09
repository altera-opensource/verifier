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

import com.intel.bkp.fpgacerts.Utils;
import com.intel.bkp.fpgacerts.exceptions.InvalidDiceCertificateSubjectException;
import com.intel.bkp.fpgacerts.model.AttFamily;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class DiceCertificateSubjectTest {

    private static final String TEST_FOLDER = "certs/dice/";

    @Test
    void parse_deviceIdSubject_Success() {
        // given
        final String fileName = "deviceid_0123456789abcdef_H-e6TM4R12mufV0ZECGRv-fzc-I.cer";
        final String deviceIdSubject = getSubjectOfCertificate(fileName);

        // when
        final var parsedSubject = DiceCertificateSubject.parse(deviceIdSubject);

        // then
        Assertions.assertEquals("Intel", parsedSubject.getCompanyName());
        Assertions.assertEquals("Agilex", parsedSubject.getFamilyName());
        Assertions.assertEquals("L0", parsedSubject.getLevel());
        Assertions.assertEquals("H-e6TM4R12mufV0Z", parsedSubject.getAdditionalData());
        Assertions.assertEquals("0123456789abcdef", parsedSubject.getDeviceId());
    }

    @Test
    void parse_enrollmentSubject_Success() {
        // given
        final String fileName = "enrollment_0123456789abcdef_00_P_K_MiGWs09f5Dt3G2CGjULJGIg.cer";
        final String enrollmentSubject = getSubjectOfCertificate(fileName);

        // when
        final var parsedSubject = DiceCertificateSubject.parse(enrollmentSubject);

        // then
        Assertions.assertEquals("Intel", parsedSubject.getCompanyName());
        Assertions.assertEquals("Agilex", parsedSubject.getFamilyName());
        Assertions.assertEquals("ER", parsedSubject.getLevel());
        Assertions.assertEquals("00", parsedSubject.getAdditionalData());
        Assertions.assertEquals("0123456789abcdef", parsedSubject.getDeviceId());
    }

    @Test
    void parse_iidUdsSubject_Success() {
        // given
        final String fileName = "iiduds_0123456789abcdef_DW43eBZHek7h0vG3.cer";
        final String iidUdsSubject = getSubjectOfCertificate(fileName);

        // when
        final var parsedSubject = DiceCertificateSubject.parse(iidUdsSubject);

        // then
        Assertions.assertEquals("Intel", parsedSubject.getCompanyName());
        Assertions.assertEquals("Agilex", parsedSubject.getFamilyName());
        Assertions.assertEquals("PU", parsedSubject.getLevel());
        Assertions.assertEquals("DW43eBZHek7h0vG3", parsedSubject.getAdditionalData());
        Assertions.assertEquals("0123456789abcdef", parsedSubject.getDeviceId());
    }

    @Test
    public void parse_InvalidSubjectDelimiter_Throws() {
        // given
        final String subjectWithInvalidDelimiter = "CN=Intel-Agilex-ER-00-0123456789abcdef";

        // when-then
        Assertions.assertThrows(InvalidDiceCertificateSubjectException.class,
            () -> DiceCertificateSubject.parse(subjectWithInvalidDelimiter));
    }

    @Test
    public void parse_TooManySubjectComponents_Throws() {
        // given
        final String subjectWithTooManyComponents = "CN=Intel:Agilex:PU:DW43eBZHek7h0vG3:0123456789abcdef:blabla";

        // when-then
        Assertions.assertThrows(InvalidDiceCertificateSubjectException.class,
            () -> DiceCertificateSubject.parse(subjectWithTooManyComponents));
    }

    @Test
    public void parse_NotEnoughSubjectComponents_Throws() {
        // given
        final String subjectWithNotEnoughComponents = "CN=Intel:Agilex:PU:DW43eBZHek7h0vG3";

        // when-then
        Assertions.assertThrows(InvalidDiceCertificateSubjectException.class,
            () -> DiceCertificateSubject.parse(subjectWithNotEnoughComponents));
    }

    @Test
    public void parse_NoCommonName_Throws() {
        // given
        final String subjectWithoutCommonName = "OU=Intel:Agilex:PU:DW43eBZHek7h0vG3";

        // when-then
        Assertions.assertThrows(InvalidDiceCertificateSubjectException.class,
            () -> DiceCertificateSubject.parse(subjectWithoutCommonName));
    }

    @Test
    public void parse_SubjectNotADomainName_Throws() {
        // given
        final String subjectNotADomainName = "not a set of RDNs";

        // when-then
        Assertions.assertThrows(InvalidDiceCertificateSubjectException.class,
            () -> DiceCertificateSubject.parse(subjectNotADomainName));
    }

    @Test
    public void parse_UnknownFamilyNameInSubject_DoesNotThrow() {
        // given
        final String subjectWithUnknownFamilyName = "CN=Intel:NonExistentFamily:ER:01:0123456789abcdef";

        // when-then
        Assertions.assertDoesNotThrow(() -> DiceCertificateSubject.parse(subjectWithUnknownFamilyName));
    }

    @Test
    public void parse_UnknownLevelInSubject_DoesNotThrow() {
        // given
        final String subjectWithUnknownLevel = "CN=Intel:Agilex:BK:01:0123456789abcdef";

        // when-then
        Assertions.assertDoesNotThrow(() -> DiceCertificateSubject.parse(subjectWithUnknownLevel));
    }

    @Test
    public void parse_SubjectWithSInvalidSki_DoesNotThrow() {
        // given
        final String subjectWithInvalidSki = "CN=Intel:Agilex:PU:blabla:0123456789abcdef";

        // when-then
        Assertions.assertDoesNotThrow(() -> DiceCertificateSubject.parse(subjectWithInvalidSki));
    }

    @Test
    public void parse_SubjectWithSvnOutOfRange_DoesNotThrow() {
        // given
        final String subjectWithSvnOutOfRange = "CN=Intel:Agilex:ER:FF:0123456789abcdef";

        // when-then
        Assertions.assertDoesNotThrow(() -> DiceCertificateSubject.parse(subjectWithSvnOutOfRange));
    }

    @Test
    public void parse_SubjectWithInvalidDeviceId_DoesNotThrow() {
        // given
        final String subjectWithInvalidDeviceId = "CN=Intel:Agilex:ER:FF:0123";

        // when-then
        Assertions.assertDoesNotThrow(() -> DiceCertificateSubject.parse(subjectWithInvalidDeviceId));
    }

    @Test
    void build_correctData_Success() {
        // given
        final var familyName = AttFamily.AGILEX.getFamilyName();
        final var levelCode = "L0";
        final var ski = "DW43eBZHek7h0vG3";
        final var deviceId = "0123456789abcdef";
        final var expectedSubject = String.format("CN=Intel:%s:%s:%s:%s", familyName, levelCode, ski, deviceId);

        // when
        final String actualSubject = DiceCertificateSubject.build(familyName, levelCode, ski, deviceId);

        // then
        Assertions.assertEquals(expectedSubject, actualSubject);
    }

    @Test
    void build_incorrectData_DoesNotThrow() {
        // given
        final var nonExistentFamilyName = "NonExistentFamily";
        final var levelCode = "XX";
        final var invalidSki = "blabla";
        final var invalidDeviceId = "blabla";
        // when
        Assertions.assertDoesNotThrow(() ->
            DiceCertificateSubject.build(nonExistentFamilyName, levelCode, invalidSki, invalidDeviceId));
    }

    @Test
    void build_svnOutOfRange_DoesNotThrow() {
        // given
        final var familyName = AttFamily.AGILEX.getFamilyName();
        final var levelCode = "L0";
        final var svnOutOfRange = "20";
        final var deviceId = "0123456789abcdef";
        // when
        Assertions.assertDoesNotThrow(
            () -> DiceCertificateSubject.build(familyName, levelCode, svnOutOfRange, deviceId));
    }

    @Test
    void toString_Success() {
        // given
        final var subject = new DiceCertificateSubject("company", "family", "level", "data", "deviceId");

        // when
        final String result = subject.toString();

        // then
        Assertions.assertEquals("CN=company:family:level:data:deviceId", result);
    }

    @SneakyThrows
    private String getSubjectOfCertificate(String fileName) {
        return Utils.readCertificate(TEST_FOLDER, fileName).getSubjectDN().getName();
    }
}
