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

package com.intel.bkp.core.psgcertificate.romext;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.EndiannessBuilder;
import com.intel.bkp.core.endianness.EndiannessStructureType;
import com.intel.bkp.core.psgcertificate.PsgCancellableBlock0EntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntryBuilder;
import com.intel.bkp.core.psgcertificate.exceptions.RomExtensionSignatureException;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

public class RomExtensionSignatureBuilder extends EndiannessBuilder<RomExtensionSignatureBuilder> {

    @Getter
    @Setter
    private PsgCertificateRootEntryBuilder psgCertRootBuilder = null;
    @Getter
    private final List<PsgCertificateEntryBuilder> psgCertEntryBuilders = new ArrayList<>();
    @Getter
    @Setter
    private PsgCancellableBlock0EntryBuilder psgCancellableBlock0EntryBuilder = null;

    private RomExtensionSignatureBuilder() {
        super(null);
    }

    @Override
    protected RomExtensionSignatureBuilder self() {
        return this;
    }

    @Override
    protected void initStructureMap(EndiannessStructureType currentStructureType, EndiannessActor currentActor) {
        // NOTHING TO DO
    }

    public static RomExtensionSignatureBuilder instance() {
        return new RomExtensionSignatureBuilder();
    }

    public RomExtensionSignatureBuilder parse(byte[] rawData) throws RomExtensionSignatureException {
        final ByteBufferSafe buffer = ByteBufferSafe.wrap(rawData);
        parseInternal(buffer);
        return this;
    }

    private void parseInternal(ByteBufferSafe buffer) throws RomExtensionSignatureException {
        List<RomExtractedStructureData> extractedStructures = new ArrayList<>();
        while (buffer.remaining() != 0) {
            extractedStructures.add(extractStructure(buffer));
        }

        for (RomExtractedStructureData data : extractedStructures) {
            data.getType().parse(this, getActor(), data.getData());
        }

        if (psgCertRootBuilder == null || psgCancellableBlock0EntryBuilder == null) {
            throw new RomExtensionSignatureException("Signature is not valid - missing one of more structures");
        }
    }

    private RomExtractedStructureData extractStructure(ByteBufferSafe buffer) throws RomExtensionSignatureException {
        try {
            buffer.mark();
            int magic = buffer.getInt(ByteOrder.LITTLE_ENDIAN);
            final int structLength = buffer.getInt(ByteOrder.LITTLE_ENDIAN);
            buffer.reset();
            final byte[] data = buffer.arrayFromInt(structLength);
            buffer.get(data);
            return new RomExtractedStructureData(magic, data);
        } catch (ByteBufferSafeException e) {
            throw new RomExtensionSignatureException("Invalid data in buffer", e);
        }
    }
}
