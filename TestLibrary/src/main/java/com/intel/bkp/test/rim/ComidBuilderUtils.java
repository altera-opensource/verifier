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

package com.intel.bkp.test.rim;

import com.intel.bkp.fpgacerts.cbor.rim.comid.Digest;
import com.intel.bkp.fpgacerts.cbor.rim.comid.EnvironmentMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.List;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ComidBuilderUtils {

    public static final String VENDOR_INTEL = "intel.com";

    public static EnvironmentMap environmentMap(String model, Integer layer, Integer index) {
        return EnvironmentMap.builder()
            .model(model)
            .vendor(VENDOR_INTEL)
            .layer(layer)
            .index(index)
            .build();
    }

    public static EnvironmentMap environmentMap(String classId, Integer layer) {
        return EnvironmentMap.builder()
            .classId(classId)
            .vendor(VENDOR_INTEL)
            .layer(layer)
            .build();
    }

    public static EnvironmentMap environmentMap(String classId) {
        return EnvironmentMap.builder()
            .classId(classId)
            .vendor(VENDOR_INTEL)
            .build();
    }

    public static MeasurementMap measurementMap(String value, String valueMask) {
        return MeasurementMap.builder()
            .rawValue(value)
            .rawValueMask(valueMask)
            .build();
    }

    public static MeasurementMap measurementMap(Integer algorithm, String digestValue) {
        return MeasurementMap.builder()
            .digests(List.of(Digest.builder()
                .algorithm(algorithm)
                .value(digestValue)
                .build()))
            .build();
    }

    public static MeasurementMap measurementMap(Integer svn, Integer algorithm, String digestValue) {
        return MeasurementMap.builder()
            .svn(svn)
            .digests(List.of(Digest.builder()
                .algorithm(algorithm)
                .value(digestValue)
                .build()))
            .build();
    }

    public static MeasurementMap versionMap(String version, String versionScheme) {
        return MeasurementMap.builder()
            .version(
                MeasurementVersion.builder()
                    .version(version)
                    .versionScheme(versionScheme)
                    .build()
            ).build();
    }
}
