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

package com.intel.bkp.verifier.model.dice;

import com.intel.bkp.ext.core.exceptions.UnknownFamilyIdException;
import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.cert.X509Certificate;

import static com.intel.bkp.ext.core.manufacturing.model.AttFamily.AGILEX;
import static com.intel.bkp.ext.utils.HexConverter.fromHex;
import static com.intel.bkp.ext.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_UEID;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UeidExtensionParserTest {

    private static final String TEST_FOLDER = "responses/";
    private static final String FIRMWARE_CERT = "firmware_certificate.der";
    private static final String DEVICE_ID = "06354FE4C1FF5E06";
    private static final X509CertificateParser X509_PARSER = new X509CertificateParser();

    private static X509Certificate firmwareCert;

    @Mock
    private X509Certificate certificate;

    private UeidExtensionParser sut;

    @BeforeAll
    static void init() throws Exception {
        firmwareCert = X509_PARSER.toX509(readCertificate(FIRMWARE_CERT));
    }

    @BeforeEach
    void setUp() {
        sut = new UeidExtensionParser();
    }

    private static byte[] readCertificate(String filename) throws Exception {
        return Utils.readFromResources(TEST_FOLDER, filename);
    }

    @Test
    void parse_Success() {
        // when
        sut.parse(firmwareCert);

        // then
        final UeidExtension parsedExtension = sut.getUeidExtension();
        Assertions.assertEquals(AGILEX.getFamilyName(), parsedExtension.getFamilyName());
        Assertions.assertEquals(AGILEX.getFamilyId(), parsedExtension.getFamilyId());
        Assertions.assertEquals(DEVICE_ID, toHex(parsedExtension.getUid()));
    }

    @Test
    void parse_NoUeidExtension_Throws() {
        // given
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(null);

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> sut.parse(certificate));
    }

    @Test
    void parse_UeidExtensionWithTooSmallValue_Throws() {
        // given
        // ueid value = octet string prefix + sequence prefix + octet string prefix + value
        final var ueidValueWithoutLastByte = "0413" + "3011" + "040F" + "020007ED0000340006354FE4C1FF5E";
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(ueidValueWithoutLastByte));

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> sut.parse(certificate));
    }

    @Test
    void parse_UeidExtensionWithTooLargeValue_Throws() {
        // given
        final var ueidValueWithAppendedByte = "0415" + "3013" + "0411" + "020007ED0000340006354FE4C1FF5E0600";
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(ueidValueWithAppendedByte));

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> sut.parse(certificate));
    }

    @Test
    void parse_UeidExtensionWithUnknownFamilyId_Throws() {
        // given
        final var ueidValueWithUnknownFamilyId = "0414" + "3012" + "0410" + "020007ED0000FF0006354FE4C1FF5E06";
        when(certificate.getExtensionValue(TCG_DICE_UEID.getOid())).thenReturn(fromHex(ueidValueWithUnknownFamilyId));

        // when-then
        Assertions.assertThrows(UnknownFamilyIdException.class, () -> sut.parse(certificate));
    }
}
