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

package com.intel.bkp.fpgacerts.cbor.signer;

import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.ProtectedHeaderType;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedMetaMap;
import com.intel.bkp.fpgacerts.cbor.rim.ProtectedSignersItem;
import com.intel.bkp.fpgacerts.cbor.rim.RimProtectedHeader;
import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.builder.RimUnsignedBuilder;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Claims;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidId;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Digest;
import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimUnsignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;
import com.intel.bkp.fpgacerts.cbor.utils.CborDateConverter;
import com.intel.bkp.test.FileUtils;
import com.intel.bkp.test.rim.OneKeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


class CoseMessage1SignerTest {

    private final CborSignatureVerifier cborSignatureVerifier = new CborSignatureVerifier();

    @Test
    void sign_WithGeneratedData_WithGeneratedSignature_Success() throws Exception {
        // given
        final AlgorithmId algorithmId = AlgorithmId.ECDSA_384;
        final byte[] rawData = FileUtils.readFromResources(TEST_FOLDER, "fw_rim_signed.rim");
        final CborKeyPair signingKey = OneKeyGenerator.generate(algorithmId);
        final RimSigned signedExpected = RimSignedParser.instance().parse(rawData);

        final byte[] payload = prepareUnsignedRim();
        final RimProtectedHeader protectedHeader = prepareProtectedRimData(algorithmId);

        // when
        final byte[] signed = CoseMessage1Signer.instance().sign(signingKey, payload, protectedHeader);
        final RimSigned signedActual = RimSignedParser.instance().parse(signed);

        // then
        assertTrue(cborSignatureVerifier.verify(signingKey.getPublicKey(), signed));
        compareParsedSignedData(signedExpected, signedActual);
        compareHexResultsWithoutSignature(rawData, signed);
    }

    @ParameterizedTest
    @EnumSource(AlgorithmId.class)
    void sign_WithGeneratedKey_Success(AlgorithmId algorithmId) throws Exception {
        // given
        final byte[] rawData = FileUtils.readFromResources(TEST_FOLDER, "fw_rim_unsigned.rim");
        final CborKeyPair signingKey = OneKeyGenerator.generate(algorithmId);
        final RimUnsigned rimUnsigned = RimUnsignedParser.instance().parse(rawData);
        final byte[] payload = RimUnsignedBuilder.instance().build(rimUnsigned);
        final RimProtectedHeader protectedHeader = prepareProtectedRimData(algorithmId);

        // when
        final byte[] signed = CoseMessage1Signer.instance().sign(signingKey, payload, protectedHeader);

        // then
        assertTrue(cborSignatureVerifier.verify(signingKey.getPublicKey(), signed));
    }

    private static RimProtectedHeader prepareProtectedRimData(AlgorithmId algorithmId) {
        return RimProtectedHeader.builder()
            .algorithmId(algorithmId)
            .contentType(ProtectedHeaderType.RIM.getContentType())
            .issuerKeyId("0000000000000000000000000000000000000000")
            .metaMap(ProtectedMetaMap.builder()
                .metaItems(
                    List.of(ProtectedSignersItem.builder()
                            .entityName("Firmware Author")
                            .build(),
                        ProtectedSignersItem.builder()
                            .entityName("CN=Intel:Agilex:ManSign")
                            .build())
                )
                .signatureValidity(CborDateConverter.fromString("9999-12-31T23:59:59Z"))
                .build())
            .build();
    }

    private static byte[] prepareUnsignedRim() {
        final List<LocatorItem> locators = new ArrayList<>();
        locators.add(new LocatorItem(LocatorType.CER,
            "https://tsci.intel.com/content/IPCS/certs/RIM_Signing_agilex_5WL28Ty-Nta3Si1dR3ralQ7jFHw.cer"));
        locators.add(new LocatorItem(LocatorType.XCORIM,
            "https://tsci.intel.com/content/IPCS/crls/RIM_Signing_agilex_5WL28Ty-Nta3Si1dR3ralQ7jFHw.xrim"));

        final var rimUnsignedGeneric = RimUnsigned.builder()
            .manifestId("51AC25B8DC58405CB4C94772120BA68A")
            .comIds(List.of(prepareComid()))
            .locators(locators)
            .profile(List.of("6086480186F84D010F06"))
            .build();
        return RimUnsignedBuilder.instance().build(rimUnsignedGeneric);
    }

    private static Comid prepareComid() {
        final var layer0Digest = "302E69BA6E3FAC340A57561234E88BFEB2FE373BCE4D4A28C244809CB467C31CA39874CD0D3F346FCA2A"
            + "9AE874A1D66B";
        final String layer1Digest = "32883E2526F54EA21FBF99642A8F56E787A0319D1D0E2AF84C36352E9A760EE80EA6C427098D17D26"
            + "F65723C0C1C66EA";
        return Comid.builder()
            .id(ComidId.builder().value("4714D26D0E044CD8BEE14EB53541B883").build())
            .entities(List.of(ComidEntity.builder()
                .entityName("Firmware manifest")
                .roles(List.of(0))
                .build()))
            .claims(Claims.builder()
                .referenceTriples(List.of(
                    ReferenceTriple.builder()
                        .environmentMap(EnvironmentMap.builder()
                            .vendor("intel.com")
                            .model("Agilex")
                            .layer(0)
                            .index(0)
                            .build())
                        .measurementMap(MeasurementMap.builder()
                            .svn(0)
                            .digests(List.of(Digest.builder()
                                .algorithm(7)
                                .value(layer0Digest)
                                .build()))
                            .build())
                        .build(),
                    ReferenceTriple.builder()
                        .environmentMap(EnvironmentMap.builder()
                            .vendor("intel.com")
                            .model("Agilex")
                            .layer(1)
                            .index(0)
                            .build())
                        .measurementMap(MeasurementMap.builder()
                            .svn(0)
                            .digests(List.of(Digest.builder()
                                .algorithm(7)
                                .value(layer1Digest)
                                .build()))
                            .build())
                        .build()))
                .endorsedTriples(List.of(ReferenceTriple.builder()
                    .environmentMap(EnvironmentMap.builder()
                        .classId("6086480186F84D010F048148")
                        .vendor("intel.com")
                        .layer(1)
                        .build())
                    .measurementMap(MeasurementMap.builder()
                        .version(MeasurementVersion.builder()
                            .version("release-2023.28.1.1")
                            .versionScheme("3")
                            .build())
                        .build())
                    .build()))
                .build())
            .build();
    }

    private static void compareParsedSignedData(RimSigned signedExpected, RimSigned signedActual) {
        assertEquals(signedExpected.getProtectedData(), signedActual.getProtectedData());
        assertEquals(signedExpected.getUnprotectedData(), signedActual.getUnprotectedData());
        assertEquals(signedExpected.getPayload(), signedActual.getPayload());
        assertNotEquals(signedExpected.getSignature(), signedActual.getSignature());
    }

    private static void compareHexResultsWithoutSignature(byte[] rawData, byte[] signed) {
        final int sha384SignatureLength = 192;
        final String hexExpected = toHex(rawData);
        final String hexActual = toHex(signed);
        assertEquals(
            hexExpected.substring(0, hexExpected.length() - sha384SignatureLength),
            hexActual.substring(0, hexActual.length() - sha384SignatureLength)
        );
    }
}
