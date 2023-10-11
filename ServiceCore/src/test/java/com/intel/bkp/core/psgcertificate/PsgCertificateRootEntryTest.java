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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.psgcertificate.model.PsgRootHashType;
import com.intel.bkp.test.KeyGenUtils;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PsgCertificateRootEntryTest {

    @Test
    void build_WithCurveSECP384R1_ReturnsSuccess() {
        // given
        KeyPair keyPair = KeyGenUtils.genEc384();

        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP384R1);

        // when
        PsgCertificateRootEntryBuilder instance = new PsgCertificateRootEntryBuilder()
            .rootHashType(PsgRootHashType.MANUFACTURING)
            .publicKey(psgPublicKeyBuilder);

        PsgCertificateRootEntryBuilder parsed = new PsgCertificateRootEntryBuilder().parse(instance.build().array());

        // then
        verifyCommonParsedAsserts(instance, parsed);
        assertEquals(instance.getRootHashType(), parsed.getRootHashType());
    }

    @Test
    void build_WithSECP256R1_ReturnsSuccess() {
        // given
        KeyPair keyPair = KeyGenUtils.genEc256();
        assert keyPair != null;

        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP256R1);

        // when
        PsgCertificateRootEntryBuilder instance = new PsgCertificateRootEntryBuilder()
            .publicKey(psgPublicKeyBuilder);

        PsgCertificateRootEntryBuilder parse = new PsgCertificateRootEntryBuilder().parse(instance.build().array());

        // then
        verifyCommonParsedAsserts(instance, parse);
    }

    @Test
    void buildForFw_ReturnsSuccess() {
        // given
        KeyPair keyPair = KeyGenUtils.genEc384();
        assert keyPair != null;

        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP384R1);

        // when
        PsgCertificateRootEntryBuilder instance = new PsgCertificateRootEntryBuilder()
            .rootHashType(PsgRootHashType.MANUFACTURING)
            .publicKey(psgPublicKeyBuilder);

        PsgCertificateRootEntryBuilder parse =
            new PsgCertificateRootEntryBuilder()
                .withActor(EndiannessActor.FIRMWARE)
                .parse(instance.withActor(EndiannessActor.FIRMWARE).build().array());

        // then
        verifyCommonParsedAsserts(instance, parse);
    }

    @Test
    void parse_WithInvalidRootEntryMagic_ThrowsException() {
        // given
        byte[] invalidCert = fromHex("892230360000009A000000820000000000000"
            + "000000000000000000000000000587006600000003100000031543266480000000000000000004A663E2F2D3C8D666D736BBF00"
            + "5532AE948A4045AE0348DD46867197560A2E8453FB31ECE94FC3BC283B449FC45CC39600CDF194B96EE2FF62D14B24D63CF46A"
            + "4AAB090587A7397E8A568AFF603E10B0ACC987E2EBF25D4E7758FCECF11AEECFBB");

        assertThrows(ParseStructureException.class,
            () -> new PsgCertificateRootEntryBuilder().parse(invalidCert));
    }

    @Test
    void parse_WithInvalidPublicKeyMagic_ThrowsException() {
        // given
        byte[] invalidCert = fromHex("892590360000009A00000082000000000000"
            + "0000000000000000000000000000931151180000003100000031543266480000000000000000004A663E2F2D3C8D666D736BBF0"
            + "05532AE948A4045AE0348DD46867197560A2E8453FB31ECE94FC3BC283B449FC45CC39600CDF194B96EE2FF62D14B24D63CF46A"
            + "4AAB090587A7397E8A568AFF603E10B0ACC987E2EBF25D4E7758FCECF11AEECFBB");

        assertThrows(ParseStructureException.class,
            () -> new PsgCertificateRootEntryBuilder().parse(invalidCert));
    }

    private void verifyCommonParsedAsserts(PsgCertificateRootEntryBuilder instance,
                                           PsgCertificateRootEntryBuilder parse) {
        PsgPublicKeyBuilder instancePubKey = instance.getPsgPublicKeyBuilder();
        PsgPublicKeyBuilder parsePubKey = parse.getPsgPublicKeyBuilder();
        assertEquals(instance.getLengthOffset(), parse.getLengthOffset());
        assertEquals(instance.getDataLength(), parse.getDataLength());
        assertEquals(instance.getMsbOfPubKey(), parse.getMsbOfPubKey());
        assertEquals(instancePubKey.getSizeX(), parsePubKey.getSizeX());
        assertEquals(instancePubKey.getSizeY(), parsePubKey.getSizeY());
        assertEquals(instancePubKey.getPublicKeyPermissions(), parsePubKey.getPublicKeyPermissions());
        assertEquals(instancePubKey.getPublicKeyCancellation(), parsePubKey.getPublicKeyCancellation());
        assertArrayEquals(instancePubKey.getCurvePoint().getAlignedDataToSize(),
            parsePubKey.getCurvePoint().getAlignedDataToSize());
        assertEquals(instancePubKey.getCurvePoint().getCurveSpec(),
            parsePubKey.getCurvePoint().getCurveSpec());
    }

    private PsgPublicKeyBuilder getPsgPublicKeyBuilder(KeyPair keyPair, PsgCurveType secp384r1) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.M1_MAGIC)
            .publicKey(keyPair.getPublic(), secp384r1);
    }
}
