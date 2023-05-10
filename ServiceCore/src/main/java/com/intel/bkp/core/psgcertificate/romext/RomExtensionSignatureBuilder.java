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

package com.intel.bkp.core.psgcertificate.romext;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.interfaces.IStructure;
import com.intel.bkp.core.psgcertificate.PsgCancellableBlock0EntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntryBuilder;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

@Getter
public class RomExtensionSignatureBuilder {

    private final List<PsgCertificateEntryBuilder> psgCertEntryBuilders = new ArrayList<>();
    @Setter(AccessLevel.PRIVATE)
    private PsgCertificateRootEntryBuilder psgCertRootBuilder;
    @Setter(AccessLevel.PRIVATE)
    private PsgCancellableBlock0EntryBuilder psgCancellableBlock0EntryBuilder;
    private EndiannessActor actor = EndiannessActor.SERVICE;

    public static RomExtensionSignatureBuilder instance() {
        return new RomExtensionSignatureBuilder();
    }

    public RomExtensionSignatureBuilder withActor(EndiannessActor actor) {
        this.actor = actor;
        return this;
    }

    public RomExtensionSignatureBuilder parse(byte[] manifestData) throws ParseStructureException {
        return parse(ByteBufferSafe.wrap(manifestData));
    }

    public RomExtensionSignatureBuilder parse(ByteBufferSafe buffer) throws ParseStructureException {
        while (buffer.remaining() != 0) {
            setStructure(extractStructure(buffer));
        }

        ensureRequiredStructuresPresent();
        return this;
    }

    private RomExtractedStructureData extractStructure(ByteBufferSafe buffer) {
        try {
            buffer.mark();
            int magic = buffer.getInt(ByteOrder.LITTLE_ENDIAN);
            final int structLength = buffer.getInt(ByteOrder.LITTLE_ENDIAN);
            buffer.reset();
            final byte[] data = buffer.arrayFromInt(structLength);
            buffer.get(data);
            return RomExtractedStructureData.from(magic, data);
        } catch (ByteBufferSafeException e) {
            throw new ParseStructureException("Invalid data in buffer", e);
        }
    }

    private void setStructure(RomExtractedStructureData extractedStructure) {
        final var data = extractedStructure.data();
        switch (extractedStructure.type()) {
            case ROOT -> setBuilder(this::setPsgCertRootBuilder, PsgCertificateRootEntryBuilder::new, data);
            case LEAF -> setBuilder(psgCertEntryBuilders::add, PsgCertificateEntryBuilder::new, data);
            case BLOCK0 -> setBuilder(this::setPsgCancellableBlock0EntryBuilder, PsgCancellableBlock0EntryBuilder::new,
                data);
        }
    }

    private <T extends StructureBuilder<T, Y>, Y extends IStructure> void setBuilder(Consumer<T> setBuilder,
                                                                                     Supplier<T> builderSupplier,
                                                                                     byte[] data) {
        setBuilder.accept(StructureBuilder.getBuilder(builderSupplier, getActor(), data));
    }

    private void ensureRequiredStructuresPresent() {
        if (psgCertRootBuilder == null || psgCancellableBlock0EntryBuilder == null) {
            throw new ParseStructureException("Signature is not valid - missing one or more required structures");
        }
    }
}
