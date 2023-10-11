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

package com.intel.bkp.verifier.service.testutils;

import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Claims;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidId;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.test.rim.RimGenerator;
import com.intel.bkp.test.rim.XrimGenerator;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.FwidHashAlg.FWIDS_HASH_ALG_SHA384;
import static com.intel.bkp.test.rim.ComidBuilderUtils.VENDOR_INTEL;
import static com.intel.bkp.test.rim.ComidBuilderUtils.environmentMap;
import static com.intel.bkp.test.rim.ComidBuilderUtils.measurementMap;
import static com.intel.bkp.test.rim.ComidBuilderUtils.versionMap;
import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.utils.PathUtils.buildPath;

public class DesignRimTestData extends TestDataBase {

    public static final String BASE_URL_PRE = "https://pre1-tsci.intel.com/content/";

    // Below digest values extracted from CoRIM file parsed with cbor.me website
    private static final String LAYER_0_DIGEST =
        "302E69BA6E3FAC340A57561234E88BFEB2FE373BCE4D4A28C244809CB467C31CA39874CD0D3F346FCA2A9AE874A1D66B";
    private static final String LAYER_1_DIGEST =
        "32883E2526F54EA21FBF99642A8F56E787A0319D1D0E2AF84C36352E9A760EE80EA6C427098D17D26F65723C0C1C66EA";
    // Below digest value is randomly generated
    private static final String LAYER_0_INDEX1_DIGEST =
        "58E352D2D00A37B69398223EDFAA1012BC7F81BEDAA8D323AF18B00E4E384FF7CA56F3C62A4BBAE6A0EC08511A93DD7F";

    private static final String FAMILY_AGILEX = Family.AGILEX.getFamilyName();

    @Override
    public TestDataDTO prepare(KeyPair keyPair) {
        final var designRimGenerator = RimGenerator.instance();
        final byte[] designSignedRimData = designRimGenerator
            .distributionPointUrl(buildPath(BASE_URL_PRE, "IPCS"))
            .layer1Digest(LAYER_1_DIGEST)
            .design(true)
            .keyPair(keyPair)
            .designComid(prepareDesignRimComid())
            .generate();

        final String rimLink = getLink(designRimGenerator.locators(), LocatorType.CORIM);

        final String testData = toHex(designSignedRimData);

        final var signedRimGenerator = RimGenerator.instance()
            .distributionPointUrl(buildPath(BASE_URL_PRE, "IPCS"))
            .layer1Digest(LAYER_1_DIGEST)
            .fwComid(prepareRimComid())
            .keyPair(keyPair);

        final byte[] generatedSignedRim = signedRimGenerator.generate();

        final List<LocatorItem> locators = signedRimGenerator.locators();
        final String xrimLink = getLink(locators, LocatorType.XCORIM);
        final String cerLink = getLink(locators, LocatorType.CER);

        final byte[] xrimContent = XrimGenerator
            .instance()
            .keyPair(keyPair)
            .generate();

        return TestDataDTO.builder()
            .deviceData(prepareMeasurementsFromDevice())
            .testData(testData)
            .cerLink(cerLink)
            .dpLinks(Map.of(
                rimLink, generatedSignedRim,
                xrimLink, xrimContent
            )).build();
    }

    @Override
    Comid prepareRimComid() {
        return Comid.builder()
            .id(ComidId.builder().value("51F505F82911480B9F44B8A614FF2B18").build())
            .entities(List.of(ComidEntity.builder()
                .entityName("Firmware manifest")
                .roles(List.of(0))
                .build()))
            .claims(Claims.builder()
                .referenceTriples(List.of(
                    ReferenceTriple.builder()
                        .environmentMap(environmentMap(FAMILY_AGILEX, 0, 1))
                        .measurementMap(measurementMap(0, 7, LAYER_0_INDEX1_DIGEST))
                        .build()))
                .endorsedTriples(List.of(ReferenceTriple.builder()
                    .environmentMap(environmentMap("6086480186F84D010F048148", 1))
                    .measurementMap(versionMap("release-2023.28.1.1", "3"))
                    .build()))
                .build())
            .build();
    }

    @Override
    List<TcbInfoMeasurement> prepareMeasurementsFromDevice() {
        final String hashAlg = FWIDS_HASH_ALG_SHA384.getOid();
        return List.of(
            new TcbInfoMeasurement(
                TcbInfoKey.builder().vendor(VENDOR_INTEL).model(FAMILY_AGILEX).layer(0).index(0).build(),
                TcbInfoValue.builder().svn(Optional.of(0)).fwid(
                    Optional.of(new FwIdField(hashAlg, LAYER_0_DIGEST))).build()
            ),
            new TcbInfoMeasurement(
                TcbInfoKey.builder().vendor(VENDOR_INTEL).model(FAMILY_AGILEX).layer(1).index(0).build(),
                TcbInfoValue.builder().svn(Optional.of(0)).fwid(
                    Optional.of(new FwIdField(hashAlg, LAYER_1_DIGEST))).build()
            ),
            new TcbInfoMeasurement(
                TcbInfoKey.builder().vendor(VENDOR_INTEL).model(FAMILY_AGILEX).layer(0).index(1).build(),
                TcbInfoValue.builder().svn(Optional.of(0)).fwid(
                    Optional.of(new FwIdField(hashAlg, LAYER_0_INDEX1_DIGEST))).build()
            )
        );
    }

    @Override
    Comid prepareDesignRimComid() {
        return Comid.builder()
            .id(ComidId.builder().value("4714D26D0E044CD8BEE14EB53541B883").build())
            .entities(List.of(ComidEntity.builder()
                .entityName("Firmware manifest")
                .roles(List.of(0))
                .build()))
            .claims(Claims.builder()
                .referenceTriples(List.of(
                    ReferenceTriple.builder()
                        .environmentMap(environmentMap(FAMILY_AGILEX, 0, 0))
                        .measurementMap(measurementMap(0, 7, LAYER_0_DIGEST))
                        .build(),
                    ReferenceTriple.builder()
                        .environmentMap(environmentMap(FAMILY_AGILEX, 1, 0))
                        .measurementMap(measurementMap(0, 7, LAYER_1_DIGEST)).build()))
                .endorsedTriples(List.of(ReferenceTriple.builder()
                    .environmentMap(environmentMap("6086480186F84D010F048148", 1))
                    .measurementMap(versionMap("release-2023.28.1.1", "3"))
                    .build()))
                .build())
            .build();
    }
}
