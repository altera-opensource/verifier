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
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.test.KeyGenUtils;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType.SECP384R1;
import static com.intel.bkp.test.KeyGenUtils.genEc256;
import static com.intel.bkp.test.SigningUtils.signEcData;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PsgCertificateEntryBuilderTest {

    @Test
    void build_returnsSuccess() {
        // given
        KeyPair keyPair = KeyGenUtils.genEc384();
        assert keyPair != null;

        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP384R1);
        PsgSignatureBuilder psgSignatureBuilder = getPsgSignatureBuilder(PsgSignatureCurveType.SECP384R1);

        // when
        byte[] result = new PsgCertificateEntryBuilder()
            .publicKey(psgPublicKeyBuilder)
            .withSignature(psgSignatureBuilder)
            .signData(dataToSign -> signEcData(dataToSign, keyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA),
                SECP384R1)
            .build()
            .array();

        PsgCertificateEntryBuilder parsed = new PsgCertificateEntryBuilder().parse(result);

        // then
        assertTrue(parsed.getDataLength() > 0);
        assertTrue(parsed.getSignatureLength() > 0);
        assertEquals(
            PsgCertificateEntryBuilder.ENTRY_BASIC_SIZE + parsed.getDataLength() + parsed.getSignatureLength(),
            parsed.getLengthOffset());
        assertNotNull(parsed.getPsgPublicKeyBuilder());
        assertNotNull(parsed.getPsgSignatureBuilder());
    }

    @Test
    void build_withEcTypeSecp256r1_returnsSuccess() {
        // given
        KeyPair keyPair = genEc256();

        PsgPublicKeyBuilder psgPublicKeyBuilder = getPsgPublicKeyBuilder(keyPair, PsgCurveType.SECP256R1);
        PsgSignatureBuilder psgSignatureBuilder = getPsgSignatureBuilder(PsgSignatureCurveType.SECP256R1);

        // when
        byte[] result = new PsgCertificateEntryBuilder()
            .publicKey(psgPublicKeyBuilder)
            .withSignature(psgSignatureBuilder)
            .withBkpPermissions()
            .withNoCancellationId()
            .signData(dataToSign -> signEcData(
                dataToSign, keyPair.getPrivate(), CryptoConstants.SHA256_WITH_ECDSA
            ), SECP384R1)
            .build()
            .array();

        PsgCertificateEntryBuilder parsed = new PsgCertificateEntryBuilder().parse(result);

        // then
        assertTrue(parsed.getDataLength() > 0);
        assertTrue(parsed.getSignatureLength() > 0);
        assertEquals(
            PsgCertificateEntryBuilder.ENTRY_BASIC_SIZE + parsed.getDataLength() + parsed.getSignatureLength(),
            parsed.getLengthOffset());
        assertNotNull(parsed.getPsgPublicKeyBuilder());
        assertNotNull(parsed.getPsgSignatureBuilder());
    }

    @Test
    void parse_withInvalidPublicKeyEntryMagic_throwsException() {
        // given
        String invalidCert = "92541917000001020000007A0000007000000000000000004065664300000062000000005432664800000000"
            + "0000000000BD09B73529E82F22523C1081ABA188C32093A8713859E22E6468F151E7BEEB799732AAF8D366137B4728993AED3D0"
            + "20F00110714A840D71608161753FF037D2D8A45C4896E29841FF0C7A209DF9A4562CF4C4A856E39D064ECD749AFD59DFB930B74"
            + "88152000000030000000303054882048F533618389CE27F0DCECF44AAFE7A771127B23FF044A19B296374F4924156A2EC719E3A"
            + "2256E41C0A3A969EFC29A72397441B273998CB3F5A80D10314A3BD1D26E970FF8378987E02B3FAD5EA375CA6BED31DD5737D697"
            + "5CBA816C4D29B0B7";

        assertThrows(ParseStructureException.class,
            () -> new PsgCertificateEntryBuilder().parse(fromHex(invalidCert))
        );
    }

    @Test
    void parse_withInvalidSignature_throwsException() {
        // given
        String invalidCert = "92540917000001020000007A0000007000000000000000004065664300000062000000005432664800000000"
            + "0000000000BD09B73529E82F22523C1081ABA188C32093A8713859E22E6468F151E7BEEB799732AAF8D366137B4728993AED3D0"
            + "20F00110714A840D71608161753FF037D2D8A45C4896E29841FF0C7A209DF9A4562CF4C4A856E39D064ECD749AFD59DFB930B74"
            + "88152000000030000000303054882048F533618389CE27F0DCECF44AAFE7A771127B23FF044A19B296374F4924156A2EC719E3A"
            + "2256E41C0A3A969EFC29A72397441B273998CB3F5A80D10314A3BD1D26E970FF8378987E02B3FAD5EA375CA6BED31DD5737D697"
            + "5CBA816C4DB0B7";

        assertThrows(ParseStructureException.class,
            () -> new PsgCertificateEntryBuilder().parse(fromHex(invalidCert))
        );
    }

    @Test
    void parse_withInvalidPublicKeyMagic_throwsException() {
        // given
        String invalidCert = "92540917000001020000007A0000007000000000000000004065564300000062000000005432664800000000"
            + "0000000000BD09B73529E82F22523C1081ABA188C32093A8713859E22E6468F151E7BEEB799732AAF8D366137B4728993AED3D0"
            + "20F00110714A840D71608161753FF037D2D8A45C4896E29841FF0C7A209DF9A4562CF4C4A856E39D064ECD749AFD59DFB930B74"
            + "88152000000030000000303054882048F533618389CE27F0DCECF44AAFE7A771127B23FF044A19B296374F4924156A2EC719E3A"
            + "2256E41C0A3A969EFC29A72397441B273998CB3F5A80D10314A3BD1D26E970FF8378987E02B3FAD5EA375CA6BED31DD5737D697"
            + "5CBA816C4D29B0B7";

        assertThrows(ParseStructureException.class,
            () -> new PsgCertificateEntryBuilder().parse(fromHex(invalidCert))
        );
    }

    @Test
    void parse_withInvalidSignatureMagic_throwsException() {
        // given
        String invalidCert = "92540917000001020000007A0000007000000000000000004065664300000062000000005432664800000000"
            + "0000000000BD09B73529E82F22523C1081ABA188C32093A8713859E22E6468F151E7BEEB799732AAF8D366137B4728993AED3D0"
            + "20F00110714A840D71608161753FF037D2D8A45C4896E29841FF0C7A209DF9A4562CF4C4A856E39D064ECD749AFD59DFB930B74"
            + "81152000000030000000303054882048F533618389CE27F0DCECF44AAFE7A771127B23FF044A19B296374F4924156A2EC719E3A"
            + "2256E41C0A3A969EFC29A72397441B273998CB3F5A80D10314A3BD1D26E970FF8378987E02B3FAD5EA375CA6BED31DD5737D697"
            + "5CBA816C4D29B0B7";

        assertThrows(ParseStructureException.class,
            () -> new PsgCertificateEntryBuilder().parse(fromHex(invalidCert))
        );
    }

    @Test
    void parse_withInvalidSignatureType_throwsException() {
        // given
        String invalidCert = "92540917000001020000007A00000070000000000000000040656643000000620000000054326648000000000"
            + "000000000BD09B73529E82F22523C1081ABA188C32093A8713859E22E6468F151E7BEEB799732AAF8D366137B4728993AED3D020"
            + "F00110714A840D71608161753FF037D2D8A45C4896E29841FF0C7A209DF9A4562CF4C4A856E39D064ECD749AFD59DFB930B74881"
            + "52000000030000000303154882048F533618389CE27F0DCECF44AAFE7A771127B23FF044A19B296374F4924156A2EC719E3A2256"
            + "E41C0A3A969EFC29A72397441B273998CB3F5A80D10314A3BD1D26E970FF8378987E02B3FAD5EA375CA6BED31DD5737D6975CBA8"
            + "16C4D29B0B7";

        assertThrows(ParseStructureException.class,
            () -> new PsgCertificateEntryBuilder().parse(fromHex(invalidCert))
        );
    }

    @Test
    void parse_withNoSignature_ReturnsSuccess() {
        // given
        String invalidCert = "92540917000001020000007A0000000000000000000000004065664300000062000000005432664800000000"
            + "0000000000BD09B73529E82F22523C1081ABA188C32093A8713859E22E6468F151E7BEEB799732AAF8D366137B4728993AED3D0"
            + "20F00110714A840D71608161753FF037D2D8A45C4896E29841FF0C7A209DF9A4562CF4C4A856E39D064ECD749AFD59DFB93";

        // when
        final PsgCertificateEntryBuilder parse = new PsgCertificateEntryBuilder()
            .parse(fromHex(invalidCert));

        // then
        assertNotNull(parse);
    }

    @Test
    void parse_withNoSignatureButSignatureLenIsProvided_throwsBufferException() {
        // given
        String invalidCert = "92540917000001020000007A0000007000000000000000004065664300000062000000005432664800000000"
            + "0000000000BD09B73529E82F22523C1081ABA188C32093A8713859E22E6468F151E7BEEB799732AAF8D366137B4728993AED3D0"
            + "20F00110714A840D71608161753FF037D2D8A45C4896E29841FF0C7A209DF9A4562CF4C4A856E39D064ECD749AFD59DFB93";

        assertThrows(ParseStructureException.class,
            () -> new PsgCertificateEntryBuilder().parse(fromHex(invalidCert)),
            "Invalid buffer during parsing entry"
        );
    }

    @Test
    void getPublicKeyRawFormat_returnsSuccess() {
        // given
        KeyPair keyPair = KeyGenUtils.genEc384();

        PsgPublicKeyBuilder psgPublicKeyBuilder = new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.M1_MAGIC)
            .publicKey(keyPair.getPublic(), PsgCurveType.SECP384R1);

        // when
        PsgCertificateEntryBuilder instance = new PsgCertificateEntryBuilder()
            .publicKey(psgPublicKeyBuilder);

        byte[] rawPubKey = instance.getPublicKeyXY();

        // then
        assertTrue(rawPubKey.length > 0);
    }

    private PsgPublicKeyBuilder getPsgPublicKeyBuilder(KeyPair keyPair, PsgCurveType psgCurveType) {
        return new PsgPublicKeyBuilder()
            .withActor(EndiannessActor.SERVICE)
            .magic(PsgPublicKeyMagic.M1_MAGIC)
            .publicKey(keyPair.getPublic(), psgCurveType);
    }

    private PsgSignatureBuilder getPsgSignatureBuilder(PsgSignatureCurveType psgSignatureCurveType) {
        return PsgSignatureBuilder.empty(psgSignatureCurveType);
    }
}
