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

package com.intel.bkp.fpgacerts.cbor.rim.parser;

import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.builder.RimUnsignedBuilder;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Claims;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidId;
import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static com.intel.bkp.test.rim.ComidBuilderUtils.environmentMap;
import static com.intel.bkp.test.rim.ComidBuilderUtils.measurementMap;
import static com.intel.bkp.test.rim.ComidBuilderUtils.versionMap;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RimSignedParserTest {

    private final RimSignedParser sut = RimSignedParser.instance();

    @Test
    void parse_Success() throws Exception {
        // given
        final byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "fw_rim_signed.rim");

        // when
        final RimSigned entity = sut.parse(cborData);

        // then
        assertNotNull(entity);
    }

    @Test
    void parse_WithDesignRim_Success() throws Exception {
        // given
        final byte[] rawSignedData = FileUtils.readFromResources(TEST_FOLDER, "design_rim_signed.rim");
        final byte[] expectedDesignRimPayload = RimUnsignedBuilder.instance().build(getUnsignedDesignRimData());

        // when
        final RimSigned rimSigned = sut.parse(rawSignedData);
        final byte[] actualDesignRimPayload = RimUnsignedBuilder.instance().build(rimSigned.getPayload());

        // then
        assertEquals("3D713C32AC3740FD37C7E65DAE8227D4C2021584", rimSigned.getProtectedData().getIssuerKeyId());
        assertEquals(toHex(expectedDesignRimPayload), toHex(actualDesignRimPayload));
    }

    private RimUnsigned getUnsignedDesignRimData() {
        final List<ReferenceTriple> referenceTriples = List.of(
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0401", 2))
                .measurementMap(measurementMap("0000000003000000", "FFFFFFFF000000FF"))
                .build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0402", 2))
                .measurementMap(measurementMap(7, "AB822974FAD8A6E3AD95916AF199AC189015CAD15613CD16"
                    + "1EC33090E9D13EBD9C21B952CAC8F856411F42238FFAA8C4")).build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0403", 2))
                .measurementMap(measurementMap(7, "C0AA77F5D2214BA0A8AE2976418A1ECC4424C996AB5EEA8F"
                    + "E9B75E0B9D167EF8ADDA90D97DE60C241F70D4AE8E52FF1F")).build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F0405", 2))
                .measurementMap(measurementMap(7, "B581557A36836ABA4BA69D9B2C4252CF29281A996C92202D"
                    + "DA2E9112FA458CBB1522367EE54E82B026E61C0B62DADF76")).build(),
            ReferenceTriple.builder()
                .environmentMap(environmentMap("6086480186F84D010F048148", 1))
                .measurementMap(versionMap("release-2021.3.4.2", "3"))
                .build()
        );

        return RimUnsigned.builder()
            .manifestId("3233665B69724ADEB629AD642AB6E34D")
            .comIds(List.of(Comid.builder()
                .id(ComidId.builder().value("5CC21C1EDC37453D8FF559AFB335371C").build())
                .entities(List.of(
                    ComidEntity.builder()
                        .entityName("Design Author")
                        .regId("")
                        .roles(List.of(0))
                        .build()
                ))
                .claims(Claims.builder()
                    .referenceTriples(referenceTriples)
                    .endorsedTriples(List.of(ReferenceTriple.builder()
                        .environmentMap(EnvironmentMap.builder()
                            .classId("6086480186F84D010F048149")
                            .vendor("intel.com")
                            .build())
                        .measurementMap(MeasurementMap.builder()
                            .version(MeasurementVersion.builder().version("").build())
                            .build())
                        .build()))
                    .build())
                .build()))
            .locators(List.of(
                new LocatorItem(LocatorType.CORIM,
                    "https://tsci.intel.com/content/IPCS/rims/agilex_L1_c3jAnhF5MTYncnRlDh_Ggr-T7lvK.rim"),
                new LocatorItem(LocatorType.NONE, ""),
                new LocatorItem(LocatorType.NONE, "")
            ))
            .profile(List.of("6086480186F84D010F06"))
            .build();
    }
}
