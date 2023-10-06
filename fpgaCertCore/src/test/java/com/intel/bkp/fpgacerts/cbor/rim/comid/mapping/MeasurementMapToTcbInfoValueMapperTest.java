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

package com.intel.bkp.fpgacerts.cbor.rim.comid.mapping;

import com.intel.bkp.fpgacerts.cbor.rim.comid.Digest;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Flags;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import com.intel.bkp.utils.MaskHelper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.FwidHashAlg.FWIDS_HASH_ALG_SHA384;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MeasurementMapToTcbInfoValueMapperTest {

    private final MeasurementMapToTcbInfoValueMapper sut = new MeasurementMapToTcbInfoValueMapper();

    @Test
    void map_WithEmptyMap_Success() {
        // given
        final var measurementMap = new MeasurementMap(null, 0, null, null, null, null);

        // when
        final TcbInfoValue result = sut.map(measurementMap);

        // then
        assertTrue(result.getVersion().isEmpty());
        assertEquals(0, result.getSvn().get());
        assertTrue(result.getFwid().isEmpty());
        assertTrue(result.getMaskedVendorInfo().isEmpty());
        assertTrue(result.getFlags().isEmpty());
    }

    @Test
    void map_WithFilledMap_Success() {
        // given
        final var versionScheme = "1";
        final var version = "release-2021.3.4.2";
        final var measurementVersion = new MeasurementVersion(version, versionScheme);
        final Integer svn = 2;
        final String hashValue =
            "066331A2C0CD05F2F48D5BDD4EA60C5CFFAE61C286B1ADDE040E1F821EC8199FF76AA3750C8DE1382CDB14B067A8E0E3";
        final var digest = new Digest(7, hashValue);
        final String rawValue = "0000000003000000";
        final String rawValueMask = "FFFFFFFF000000FF";
        final var flags = new Flags(false, true, false, true, false, false);
        final var measurementMap =
            new MeasurementMap(measurementVersion, svn, List.of(digest), flags, rawValue, rawValueMask);

        // when
        final TcbInfoValue result = sut.map(measurementMap);

        // then
        assertEquals(version, result.getVersion().get());
        assertEquals(svn, result.getSvn().get());
        assertEquals(new FwIdField(FWIDS_HASH_ALG_SHA384.getOid(), hashValue), result.getFwid().get());
        assertEquals(new MaskedVendorInfo(rawValue, rawValueMask), result.getMaskedVendorInfo().get());
        assertTrue(result.getFlags().isEmpty());
    }

    @Test
    void map_WithRawValueButNoRawValueMask_Success() {
        // given
        final String rawValue = "0000000003000000";
        final String rawValueMask = null;
        final String defaultMask = MaskHelper.getMask(rawValue.length());
        final var measurementMap =
            new MeasurementMap(null, 0, null, null, rawValue, rawValueMask);

        // when
        final TcbInfoValue result = sut.map(measurementMap);

        // then
        assertTrue(result.getMaskedVendorInfo().isPresent());
        assertEquals(new MaskedVendorInfo(rawValue, defaultMask), result.getMaskedVendorInfo().get());
    }

    @Test
    void map_WithRawValueMaskButNoRawValue_Success() {
        // given
        final String rawValue = null;
        final String rawValueMask = "FFFFFFFF000000FF";
        final var measurementMap =
            new MeasurementMap(null, 0, null, null, rawValue, rawValueMask);

        // when
        final TcbInfoValue result = sut.map(measurementMap);

        // then
        assertTrue(result.getMaskedVendorInfo().isEmpty());
    }
}
