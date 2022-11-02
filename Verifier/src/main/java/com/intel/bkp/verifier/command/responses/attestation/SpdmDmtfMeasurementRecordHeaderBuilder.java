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

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.verifier.command.maps.SpdmDmtfMeasurementHeaderEndianessMapImpl;
import com.intel.bkp.verifier.command.responses.BaseResponseBuilder;
import com.intel.bkp.verifier.endianess.EndianessStructureFields;
import com.intel.bkp.verifier.endianess.EndianessStructureType;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SpdmDmtfMeasurementRecordHeaderBuilder
    extends BaseResponseBuilder<SpdmDmtfMeasurementRecordHeaderBuilder> {

    public static final int HEADER_SIZE = 3;
    private byte type = 0;
    private short size = 0;

    @Override
    public EndianessStructureType currentStructureMap() {
        return EndianessStructureType.SPDM_DMTF_MEASUREMENT_HEADER;
    }

    @Override
    public SpdmDmtfMeasurementRecordHeaderBuilder withActor(EndianessActor actor) {
        changeActor(actor);
        return this;
    }

    @Override
    public void initStructureMap(EndianessStructureType currentStructureType, EndianessActor currentActor) {
        maps.put(currentStructureType, new SpdmDmtfMeasurementHeaderEndianessMapImpl(currentActor));
    }

    public SpdmDmtfMeasurementHeader build() {
        final var header = new SpdmDmtfMeasurementHeader();
        header.setType(type);
        header.setSize(convertShort(size, EndianessStructureFields.SPDM_DMTF_MEASUREMENT_HEADER_LEN));
        return header;
    }

    public SpdmDmtfMeasurementRecordHeaderBuilder parse(ByteBufferSafe buffer) {
        type = buffer.getByte();
        size = buffer.getShort();

        size = convertShort(size, EndianessStructureFields.SPDM_DMTF_MEASUREMENT_HEADER_LEN);

        return this;
    }
}
