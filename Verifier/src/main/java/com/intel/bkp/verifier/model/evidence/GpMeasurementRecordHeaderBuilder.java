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

package com.intel.bkp.verifier.model.evidence;

import com.intel.bkp.utils.ByteBufferSafe;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteOrder;

@Getter
@Setter
public class GpMeasurementRecordHeaderBuilder implements IMeasurementRecordHeaderBuilder<GpMeasurementRecordHeader> {

    public static final int HEADER_SIZE = 8;

    private byte measurementWithHeaderSize = 0;
    private byte reserved = 0;
    private byte flags = 0;
    private byte sectionType = 0;
    private int sectionIndex = 0;

    @Override
    public boolean canBeParsed(ByteBufferSafe buffer) {
        return buffer.remaining() > HEADER_SIZE;
    }

    @Override
    public GpMeasurementRecordHeaderBuilder parse(ByteBufferSafe buffer) {
        measurementWithHeaderSize = buffer.getByte();
        reserved = buffer.getByte();
        flags = buffer.getByte();
        sectionType = buffer.getByte();
        sectionIndex = buffer.getInt(ByteOrder.LITTLE_ENDIAN);
        return this;
    }

    @Override
    public GpMeasurementRecordHeader build() {
        final var header = new GpMeasurementRecordHeader();
        header.setMeasurementWithHeaderSize(measurementWithHeaderSize);
        header.setReserved(reserved);
        header.setFlags(flags);
        header.setSectionType(sectionType);
        header.setSectionIndex(sectionIndex);
        return header;
    }
}
