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

package com.intel.bkp.fpgacerts.url.params.parsing;

import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateSubject;
import com.intel.bkp.fpgacerts.exceptions.InvalidDiceCertificateSubjectException;
import com.intel.bkp.fpgacerts.url.params.DiceParams;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiceParamsParserBaseTest {

    public static final String SKI = "AQIDBAUGBwgJCgsMAAAAAAAAAAA";
    public static final String MATCHING_SKI_IN_SUBJECT = SKI.substring(0, 12);
    public static final String DIFFERENT_SKI_IN_SUBJECT = "AbCdEfGhIjKl";
    public static final byte[] FIRST_20_SKI_BYTES = Base64.getUrlDecoder().decode(SKI);
    public static final String DEVICE_ID = "0102030405060708";
    public static final DiceParams EXPECTED_PARAMS = new DiceParams(SKI, DEVICE_ID);
    public static final String INVALID_DEVICE_ID = "invalid";
    public static final String LEVEL = "L0";
    public static final String INVALID_LEVEL = "IN";
    public static final String SUBJECT_FORMAT = "CN=Intel:Agilex:%s:%s:%s";

    @Mock
    private X509Certificate x509Certificate;

    @Spy
    private DiceParamsParserTestImpl sut = new DiceParamsParserTestImpl();

    @BeforeEach
    void setup() {
        setupCertificateSubjectKeyIdentifier(FIRST_20_SKI_BYTES);
    }

    @Test
    public void parse_Success() {
        // given
        final var subject = SUBJECT_FORMAT.formatted(LEVEL, MATCHING_SKI_IN_SUBJECT, DEVICE_ID);
        setupCertificateSubject(subject);

        // when
        final DiceParams actualParams = sut.parse(x509Certificate);

        // then
        verify(sut).getDiceParams(SKI, DiceCertificateSubject.parse(subject));
        assertEquals(EXPECTED_PARAMS, actualParams);
    }

    @Test
    public void parse_MismatchedSkiInSubject_UsesCalculatedSki() {
        // given
        final var subject = SUBJECT_FORMAT.formatted(LEVEL, DIFFERENT_SKI_IN_SUBJECT, DEVICE_ID);
        setupCertificateSubject(subject);

        // when
        final DiceParams actualParams = sut.parse(x509Certificate);

        // then
        verify(sut).getDiceParams(SKI, DiceCertificateSubject.parse(subject));
        assertEquals(EXPECTED_PARAMS, actualParams);
    }

    @Test
    public void parse_UnknownLevelInSubject_DoesNotThrow() {
        // given
        final var subject = SUBJECT_FORMAT.formatted(INVALID_LEVEL, MATCHING_SKI_IN_SUBJECT, DEVICE_ID);
        setupCertificateSubject(subject);

        // when-then
        assertDoesNotThrow(() -> sut.parse(x509Certificate));
    }

    @Test
    public void parse_InvalidDeviceId_DoesNotThrow() {
        // given
        final var subject = SUBJECT_FORMAT.formatted(LEVEL, MATCHING_SKI_IN_SUBJECT, INVALID_DEVICE_ID);
        setupCertificateSubject(subject);

        // when-then
        assertDoesNotThrow(() -> sut.parse(x509Certificate));
    }

    @Test
    public void parse_InvalidSubjectDelimiter_Throws() {
        // given
        setupCertificateSubject("CN=Intel-Agilex-ER-01-DW43eBZHek7h0vG3");

        // when-then
        assertThrows(InvalidDiceCertificateSubjectException.class,
            () -> sut.parse(x509Certificate));
    }

    @Test
    public void parse_InvalidSubjectComponentsCount_Throws() {
        // given
        setupCertificateSubject("CN=Intel:Agilex:ER:01:DW43eBZHek7h0vG3:somethingElse");

        // when-then
        assertThrows(InvalidDiceCertificateSubjectException.class,
            () -> sut.parse(x509Certificate));
    }

    private void setupCertificateSubject(String subject) {
        when(x509Certificate.getSubjectX500Principal()).thenReturn(new X500Principal(subject));
    }

    private void setupCertificateSubjectKeyIdentifier(byte[] ski) {
        final byte[] skiPrefix = new byte[]{0x04, 0x16, 0x04, 0x14};
        final byte[] skiExtensionValue = ArrayUtils.addAll(skiPrefix, ski);
        when(x509Certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId())).thenReturn(skiExtensionValue);
    }

    private class DiceParamsParserTestImpl extends DiceParamsParserBase<DiceParams> {

        public DiceParamsParserTestImpl() {
            super(new CertificateSubjectMapper());
        }

        @Override
        protected DiceParams getDiceParams(String ski, DiceCertificateSubject subject) {
            return EXPECTED_PARAMS;
        }
    }
}
