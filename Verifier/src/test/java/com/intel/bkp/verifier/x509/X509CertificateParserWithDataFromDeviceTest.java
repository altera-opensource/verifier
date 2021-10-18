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

import com.intel.bkp.verifier.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

@ExtendWith(MockitoExtension.class)
class X509CertificateParserWithDataFromDeviceTest {

    private static final String TEST_FOLDER = "responses/";

    private static final String ALIAS_CERT = "alias_certificate.der";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final String DEVICE_ID_SELF_SIGNED_CERT = "device_id_self-signed_certificate.der";
    private static final String DEVICE_ID_ENROLLMENT_CERT = "device_id_enrollment_certificate.der";
    private static final String ENROLLMENT_SELF_SIGNED_CERT = "enrollment_self-signed_certificate.der";

    private static final String ALIAS_CERT_SUBJECT =
        "CN=Intel:Agilex:L2:Xbjs_MwqqXrmRI5g:065effc1e44f3506";
    private static final String FIRMWARE_CERT_SUBJECT =
        "CN=Intel:Agilex:L1:ZaIRMTvTn00ha4bR:065effc1e44f3506";
    private static final String DEVICE_ID_SELF_SIGNED_CERT_SUBJECT =
        "CN=Intel:Agilex:L0:DI931bRmuixmLyW4:065effc1e44f3506";
    private static final String DEVICE_ID_ENROLLMENT_CERT_SUBJECT =
        "CN=Intel:Agilex:L0:DI931bRmuixmLyW4:065effc1e44f3506";
    private static final String ENROLLMENT_SELF_SIGNED_CERT_SUBJECT =
        "CN=Intel:Agilex:ER:00:065effc1e44f3506";

    private static byte[] aliasCert;
    private static byte[] firmwareCert;
    private static byte[] deviceIdSelfSignedCert;
    private static byte[] deviceIdEnrollmentCert;
    private static byte[] enrollmentSelfSignedCert;

    @InjectMocks
    private X509CertificateParser sut;

    @BeforeAll
    static void init() throws Exception {
        aliasCert = readCertificate(ALIAS_CERT);
        firmwareCert = readCertificate(FIRMWARE_CERT);
        deviceIdSelfSignedCert = readCertificate(DEVICE_ID_SELF_SIGNED_CERT);
        deviceIdEnrollmentCert = readCertificate(DEVICE_ID_ENROLLMENT_CERT);
        enrollmentSelfSignedCert = readCertificate(ENROLLMENT_SELF_SIGNED_CERT);
    }

    private static byte[] readCertificate(String filename) throws Exception {
        return Utils.readFromResources(TEST_FOLDER, filename);
    }

    @Test
    void toX509_WithAlias() {
        // when
        X509Certificate result = sut.toX509(aliasCert);

        // then
        Assertions.assertEquals(ALIAS_CERT_SUBJECT.toLowerCase(), getSubject(result));
    }

    @Test
    void toX509_WithFirmware() {
        // when
        X509Certificate result = sut.toX509(firmwareCert);

        // then
        Assertions.assertEquals(FIRMWARE_CERT_SUBJECT.toLowerCase(), getSubject(result));
    }

    @Test
    void toX509_WithDeviceIdSelfSigned() {
        // when
        X509Certificate result = sut.toX509(deviceIdSelfSignedCert);

        // then
        Assertions.assertEquals(DEVICE_ID_SELF_SIGNED_CERT_SUBJECT.toLowerCase(), getSubject(result));
    }

    @Test
    void toX509_WithDeviceIdEnrollment() {
        // when
        X509Certificate result = sut.toX509(deviceIdEnrollmentCert);

        // then
        Assertions.assertEquals(DEVICE_ID_ENROLLMENT_CERT_SUBJECT.toLowerCase(), getSubject(result));
    }

    @Test
    void toX509_WithEnrollmentSelfSigned() {
        // when
        X509Certificate result = sut.toX509(enrollmentSelfSignedCert);

        // then
        Assertions.assertEquals(ENROLLMENT_SELF_SIGNED_CERT_SUBJECT.toLowerCase(), getSubject(result));
    }

    private String getSubject(X509Certificate result) {
        return result.getSubjectDN().toString().toLowerCase();
    }
}
