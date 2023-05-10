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

package com.intel.bkp.verifier.command.responses.attestation;

import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.verifier.endianness.StructureType;
import lombok.Getter;
import lombok.Setter;

import static com.intel.bkp.verifier.endianness.StructureField.SPDM_DMTF_MEASUREMENT_HEADER_LEN;

@Setter
@Getter
public class SpdmDmtfMeasurementRecordHeaderBuilder
    extends StructureBuilder<SpdmDmtfMeasurementRecordHeaderBuilder, SpdmDmtfMeasurementHeader> {

    public static final int HEADER_SIZE = 3;
    private byte type = 0;
    private short size = 0;

    public SpdmDmtfMeasurementRecordHeaderBuilder() {
        super(StructureType.SPDM_DMTF_MEASUREMENT_HEADER);
    }

    @Override
    public SpdmDmtfMeasurementRecordHeaderBuilder self() {
        return this;
    }

    @Override
    public SpdmDmtfMeasurementHeader build() {
        final var header = new SpdmDmtfMeasurementHeader();
        header.setType(type);
        header.setSize(convertShort(size, SPDM_DMTF_MEASUREMENT_HEADER_LEN));
        return header;
    }

    @Override
    public SpdmDmtfMeasurementRecordHeaderBuilder parse(ByteBufferSafe buffer) {
        type = buffer.getByte();
        size = buffer.getShort();

        size = convertShort(size, SPDM_DMTF_MEASUREMENT_HEADER_LEN);

        return this;
    }
}
