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

package com.intel.bkp.verifier.command.responses.attestation;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.verifier.exceptions.SectionTypeException;
import com.intel.bkp.verifier.interfaces.IMeasurementRecordToTcbInfoMapper;
import com.intel.bkp.verifier.model.evidence.GpMeasurementRecordHeader;
import com.intel.bkp.verifier.model.evidence.GpMeasurementRecordHeaderBuilder;
import com.intel.bkp.verifier.model.evidence.SectionType;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class GpMeasurementRecordToTcbInfoMapper
    extends BaseMeasurementRecordToTcbInfoMapper<GpMeasurementRecordHeader>
    implements IMeasurementRecordToTcbInfoMapper<GpMeasurementRecordHeader> {

    @Override
    public TcbInfo map(GpMeasurementRecordHeader header, ByteBufferSafe recordContentBuffer) {
        try {
            final SectionType sectionType = SectionType.from(header.getSectionType());
            return mapInternal(header, recordContentBuffer, sectionType);
        } catch (SectionTypeException e) {
            log.warn("Could not parse section - section unknown: {}", header);
            recordContentBuffer.skip(getMeasurementSize(header));
            return new TcbInfo();
        }
    }

    @Override
    protected int getPrSectionIndex(GpMeasurementRecordHeader header) {
        return header.getSectionIndex();
    }

    @Override
    protected int getMeasurementSize(GpMeasurementRecordHeader header) {
        return header.getMeasurementWithHeaderSize() - GpMeasurementRecordHeaderBuilder.HEADER_SIZE;
    }
}
