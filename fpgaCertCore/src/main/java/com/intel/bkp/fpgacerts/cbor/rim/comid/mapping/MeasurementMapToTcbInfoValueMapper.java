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

import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementMap;
import com.intel.bkp.fpgacerts.cbor.rim.comid.MeasurementVersion;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import org.apache.commons.lang3.StringUtils;

import java.util.Optional;

public class MeasurementMapToTcbInfoValueMapper {

    private final DigestsToFwIdFieldMapper fwIdFieldMapper = new DigestsToFwIdFieldMapper();

    public TcbInfoValue map(MeasurementMap measurementMap) {
        return TcbInfoValue.builder()
            .version(getVersion(measurementMap))
            .svn(getSvn(measurementMap))
            .fwid(getFwid(measurementMap))
            .maskedVendorInfo(getMaskedVendorInfo(measurementMap))
            .flags(getFlags(measurementMap))
            .build();
    }

    private Optional<String> getFlags(MeasurementMap measurementMap) {
        // TODO: Implement flags mapping - probably we should stop using String as flags in TcbInfoValue
        return Optional.empty();
    }

    private Optional<MaskedVendorInfo> getMaskedVendorInfo(MeasurementMap measurementMap) {
        return Optional.ofNullable(measurementMap.getRawValue())
            .filter(StringUtils::isNotBlank)
            .map(value -> new MaskedVendorInfo(value, measurementMap.getRawValueMask()));
    }

    private static Optional<Integer> getSvn(MeasurementMap measurementMap) {
        return Optional.ofNullable(measurementMap.getSvn());
    }

    private Optional<FwIdField> getFwid(MeasurementMap measurementMap) {
        return Optional.ofNullable(measurementMap.getDigests()).map(fwIdFieldMapper::map);
    }

    private static Optional<String> getVersion(MeasurementMap measurementMap) {
        return Optional.ofNullable(measurementMap.getVersion()).map(MeasurementVersion::getVersion);
    }
}

