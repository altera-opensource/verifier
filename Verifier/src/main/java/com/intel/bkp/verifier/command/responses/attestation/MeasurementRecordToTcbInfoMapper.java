/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.command.responses.attestation;

import com.intel.bkp.ext.utils.ByteBufferSafe;
import com.intel.bkp.verifier.model.dice.FwIdField;
import com.intel.bkp.verifier.model.dice.TcbInfo;
import com.intel.bkp.verifier.model.dice.TcbInfoField;
import com.intel.bkp.verifier.model.evidence.MeasurementRecordHeader;
import com.intel.bkp.verifier.model.evidence.SectionType;

import java.util.Locale;
import java.util.Map;

public class MeasurementRecordToTcbInfoMapper {

    private static final String VENDOR = "intel.com";
    private static final String TYPE_PREFIX = "2.16.840.1.113741.1.15.4.";
    private static final String SHA384_HASH_ALG = "2.16.840.1.101.3.4.2.2";
    private static final int LAYER = 2;

    public TcbInfo map(MeasurementRecordHeader header, ByteBufferSafe recordContentBuffer) {
        final SectionType sectionType = header.getSectionType();

        final TcbInfo tcbInfo = new TcbInfo();
        final Map<TcbInfoField, Object> map = tcbInfo.getTcbInfo();
        createBaseMap(map, sectionType);

        if (SectionType.PR == sectionType) {
            map.put(TcbInfoField.INDEX, header.getSectionIndex());
        }

        if (SectionType.DEVICE_STATE == sectionType) {
            map.put(TcbInfoField.VENDOR_INFO, new DeviceStateMeasurementRecord(recordContentBuffer).getData());
        } else {
            map.put(TcbInfoField.FWIDS, new FwIdField(SHA384_HASH_ALG,
                new UserDesignMeasurementRecord(recordContentBuffer).getData())
            );
        }

        return tcbInfo;
    }

    private void createBaseMap(Map<TcbInfoField, Object> map, SectionType sectionType) {
        map.put(TcbInfoField.VENDOR, VENDOR.toUpperCase(Locale.ROOT));
        map.put(TcbInfoField.TYPE, TYPE_PREFIX + sectionType.getValue());
        map.put(TcbInfoField.LAYER, LAYER);
    }
}
