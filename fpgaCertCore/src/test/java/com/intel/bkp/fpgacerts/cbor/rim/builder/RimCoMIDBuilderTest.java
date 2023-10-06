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

package com.intel.bkp.fpgacerts.cbor.rim.builder;

import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Claims;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidEntity;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ComidId;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Digest;
import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RimCoMIDBuilderTest {

    private final RimCoMIDBuilder sut = RimCoMIDBuilder.instance();

    @Test
    void build_Success() throws Exception {
        // given
        final byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "rim_unsigned_comid.cbor");
        final Comid entity = prepareEntity();

        // when
        final byte[] actual = sut.build(entity);

        // then
        assertEquals(toHex(cborData), toHex(actual));
    }

    private static Comid prepareEntity() {
        return Comid.builder()
            .id(ComidId.builder().value("51F505F82911480B9F44B8A614FF2B18").build())
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
                                .value("3BD9C16922CD93CC29F8FE27107FC6456068FC0504A8B84476EA5F2A2342D07B794957152DDE6A"
                                    + "7D857C8176BC35FB629BF5B6F6726DC15FC01FB9AC3074BE2C")
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
                                .value("32883E2526F54EA21FBF99642A8F56E787A0319D1D0E2AF84C36352E9A760EE80EA6C42709"
                                    + "8D17D26F65723C0C1C66EA")
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
}
