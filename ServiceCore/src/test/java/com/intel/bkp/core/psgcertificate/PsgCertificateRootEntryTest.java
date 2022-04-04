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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.TestUtil;
import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.psgcertificate.model.PsgRootHashType;
import com.intel.bkp.crypto.constants.CryptoConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;

import static com.intel.bkp.utils.HexConverter.fromHex;

public class PsgCertificateRootEntryTest {

    @Test
    void build_WithCurveSECP384R1_ReturnsSuccess() throws PsgCertificateException {
        // given
        KeyPair keyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_384);
        assert keyPair != null;

        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP384R1);

        // when
        PsgCertificateRootEntryBuilder instance = new PsgCertificateRootEntryBuilder()
            .rootHashType(PsgRootHashType.MANUFACTURING)
            .publicKey(psgPublicKeyBuilder);

        PsgCertificateRootEntryBuilder parsed = new PsgCertificateRootEntryBuilder().parse(instance.build().array());

        // then
        verifyCommonParsedAsserts(instance, parsed);
        Assertions.assertEquals(instance.getRootHashType(), parsed.getRootHashType());
    }

    @Test
    void build_WithSECP256R1_ReturnsSuccess() throws PsgCertificateException {
        // given
        KeyPair keyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_256);
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
    void buildForFw_ReturnsSuccess() throws PsgCertificateException {
        // given
        KeyPair keyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_384);
        assert keyPair != null;

        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP384R1);

        // when
        PsgCertificateRootEntryBuilder instance = new PsgCertificateRootEntryBuilder()
            .rootHashType(PsgRootHashType.MANUFACTURING)
            .publicKey(psgPublicKeyBuilder);

        PsgCertificateRootEntryBuilder parse =
            new PsgCertificateRootEntryBuilder()
                .withActor(EndianessActor.FIRMWARE)
                .parse(instance.withActor(EndianessActor.FIRMWARE).build().array());

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

        Assertions.assertThrows(PsgCertificateException.class, () -> {
            new PsgCertificateRootEntryBuilder().parse(invalidCert);
        });
    }

    @Test
    void parse_WithInvalidPublicKeyMagic_ThrowsException() {
        // given
        byte[] invalidCert = fromHex("892590360000009A00000082000000000000"
            + "0000000000000000000000000000931151180000003100000031543266480000000000000000004A663E2F2D3C8D666D736BBF0"
            + "05532AE948A4045AE0348DD46867197560A2E8453FB31ECE94FC3BC283B449FC45CC39600CDF194B96EE2FF62D14B24D63CF46A"
            + "4AAB090587A7397E8A568AFF603E10B0ACC987E2EBF25D4E7758FCECF11AEECFBB");

        Assertions.assertThrows(PsgCertificateException.class, () -> {
            new PsgCertificateRootEntryBuilder().parse(invalidCert);
        });
    }

    private void verifyCommonParsedAsserts(PsgCertificateRootEntryBuilder instance,
                                           PsgCertificateRootEntryBuilder parse) {
        PsgPublicKeyBuilder instancePubKey = instance.getPsgPublicKeyBuilder();
        PsgPublicKeyBuilder parsePubKey = parse.getPsgPublicKeyBuilder();
        Assertions.assertEquals(instance.getLengthOffset(), parse.getLengthOffset());
        Assertions.assertEquals(instance.getDataLength(), parse.getDataLength());
        Assertions.assertEquals(instance.getMsbOfPubKey(), parse.getMsbOfPubKey());
        Assertions.assertEquals(instancePubKey.getSizeX(), parsePubKey.getSizeX());
        Assertions.assertEquals(instancePubKey.getSizeY(), parsePubKey.getSizeY());
        Assertions.assertEquals(instancePubKey.getPublicKeyPermissions(), parsePubKey.getPublicKeyPermissions());
        Assertions.assertEquals(instancePubKey.getPublicKeyCancellation(), parsePubKey.getPublicKeyCancellation());
        Assertions.assertArrayEquals(instancePubKey.getPointX(), parsePubKey.getPointX());
        Assertions.assertArrayEquals(instancePubKey.getPointY(), parsePubKey.getPointY());
        Assertions.assertEquals(instancePubKey.getCurveType(), parsePubKey.getCurveType());
    }

    private PsgPublicKeyBuilder getPsgPublicKeyBuilder(KeyPair keyPair, PsgCurveType secp384r1) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.M1_MAGIC)
            .curveType(secp384r1)
            .publicKey((ECPublicKey) keyPair.getPublic());
    }
}
