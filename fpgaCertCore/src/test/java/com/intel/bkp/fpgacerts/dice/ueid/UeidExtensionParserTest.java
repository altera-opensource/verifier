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

package com.intel.bkp.fpgacerts.dice.ueid;

import ch.qos.logback.classic.Level;
import com.intel.bkp.fpgacerts.LoggerTestUtil;
import com.intel.bkp.fpgacerts.Utils;
import com.intel.bkp.fpgacerts.exceptions.UnknownFamilyIdException;
import com.intel.bkp.fpgacerts.utils.BaseExtensionParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

import static com.intel.bkp.fpgacerts.model.AttFamily.AGILEX;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_UEID;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UeidExtensionParserTest {

    private LoggerTestUtil loggerTestUtil;
    private LoggerTestUtil loggerTestUtilBaseClass;

    private static final String TEST_FOLDER = "certs/dice/";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final String SUBJECT = "CN=Intel:Agilex:L1:ZaIRMTvTn00ha4bR:065effc1e44f3506";
    private static final String DEVICE_ID = "06354FE4C1FF5E06";

    private static X509Certificate firmwareCert;

    @Mock
    private X509Certificate certificate;

    private UeidExtensionParser sut;

    @BeforeAll
    static void init() throws Exception {
        firmwareCert = Utils.readCertificate(TEST_FOLDER, FIRMWARE_CERT);
    }

    @BeforeEach
    void setUp() {
        sut = new UeidExtensionParser();
        loggerTestUtil = LoggerTestUtil.instance(sut.getClass());
        loggerTestUtilBaseClass = LoggerTestUtil.instance(BaseExtensionParser.class);
    }

    @AfterEach
    void clearLogs() {
        loggerTestUtil.reset();
        loggerTestUtilBaseClass.reset();
    }

    @Test
    void parse_Success() {
        // given
        final String parsingStartMessage = "Parsing UEID extension from certificate: " + SUBJECT;
        final String parsingFinishedMessage =
            "Parsed UEID Extension. FAMILY_NAME = %s, UID = %s".formatted(AGILEX.getFamilyName(), DEVICE_ID);

        // when
        final UeidExtension parsedExtension = sut.parse(firmwareCert);

        // then
        assertEquals(AGILEX.getFamilyName(), parsedExtension.getFamilyName());
        assertEquals(AGILEX.getFamilyId(), parsedExtension.getFamilyId());
        assertEquals(DEVICE_ID, toHex(parsedExtension.getUid()));

        assertTrue(loggerTestUtilBaseClass.contains(parsingStartMessage, Level.TRACE));
        assertTrue(loggerTestUtil.contains(parsingFinishedMessage, Level.TRACE));
    }

    @Test
    void parse_NoUeidExtension_Throws() {
        // given
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(null);

        // when-then
        verifyParsingThrowsIllegalArgument();
    }

    @Test
    void parse_UeidExtensionWithTooSmallValue_Throws() {
        // given
        // ueid value = octet string prefix + sequence prefix + octet string prefix + value
        final var ueidValueWithoutLastByte = "0413" + "3011" + "040F" + "020007ED0000340006354FE4C1FF5E";
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(ueidValueWithoutLastByte));

        // when-then
        verifyParsingThrowsIllegalArgument();
    }

    @Test
    void parse_UeidExtensionWithTooLargeValue_Throws() {
        // given
        final var ueidValueWithAppendedByte = "0415" + "3013" + "0411" + "020007ED0000340006354FE4C1FF5E0600";
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(ueidValueWithAppendedByte));

        // when-then
        verifyParsingThrowsIllegalArgument();
    }

    @Test
    void parse_UeidExtensionWithUnknownFamilyId_Throws() {
        // given
        final var ueidValueWithUnknownFamilyId = "0414" + "3012" + "0410" + "020007ED0000FF0006354FE4C1FF5E06";
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(ueidValueWithUnknownFamilyId));

        // when-then
        assertThrows(UnknownFamilyIdException.class, () -> sut.parse(certificate));
    }

    private void verifyParsingThrowsIllegalArgument() {
        // given
        final String parsingError = "Failed to parse UEID extension from certificate: " + SUBJECT;
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(SUBJECT));

        // when-then
        final var ex = assertThrows(IllegalArgumentException.class, () -> sut.parse(certificate));
        assertEquals(parsingError, ex.getMessage());
    }

}
