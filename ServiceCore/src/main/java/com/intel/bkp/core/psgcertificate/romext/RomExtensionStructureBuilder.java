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
import com.intel.bkp.core.endianness.StructureType;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.interfaces.ISignBytes;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import lombok.Getter;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import static com.intel.bkp.core.endianness.EndiannessActor.FIRMWARE;
import static com.intel.bkp.core.endianness.StructureField.ROM_EXT_EDI_ID;
import static com.intel.bkp.core.endianness.StructureField.ROM_EXT_LENGTH;
import static com.intel.bkp.core.endianness.StructureField.ROM_EXT_MAGIC;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionStructure.BUILD_IDENTIFIER_LEN;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionStructure.EDI_ID_LEN;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionStructure.FAMILY_ID_LEN;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionStructure.LENGTH_LEN;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionStructure.MAGIC_LEN;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionStructure.RESERVED_LEN;
import static com.intel.bkp.core.psgcertificate.romext.RomExtensionStructure.UNUSED_FIXED_SIZE_LEN;
import static com.intel.bkp.utils.ByteConverter.toBytes;
import static com.intel.bkp.utils.HexConverter.toFormattedHex;

@Getter
public class RomExtensionStructureBuilder extends StructureBuilder<RomExtensionStructureBuilder,
    RomExtensionStructure> {

    public static final int MAGIC = 0x70539217;

    private int length = countBaseCapacity();
    private byte[] unusedFixedSize = new byte[UNUSED_FIXED_SIZE_LEN];
    private int ediId;
    private byte[] unusedVarySize = new byte[0];
    private byte[] buildIdentifier = new byte[BUILD_IDENTIFIER_LEN];
    private byte familyId;
    private final byte[] reserved = new byte[RESERVED_LEN];
    private byte[] signature = new byte[0];
    private RomExtensionSignatureBuilder romExtSigBuilder = null;

    public RomExtensionStructureBuilder() {
        super(StructureType.ROM_EXT);
    }

    @Override
    public RomExtensionStructureBuilder self() {
        return this;
    }

    public RomExtensionStructureBuilder withUnusedFixedSize(byte[] data) {
        this.unusedFixedSize = data;
        return this;
    }

    public RomExtensionStructureBuilder withFamily(byte familyId) {
        this.familyId = familyId;
        return this;
    }

    public RomExtensionStructureBuilder withEdiId(int ediId) {
        this.ediId = ediId;
        return this;
    }

    public RomExtensionStructureBuilder withUnusedVarySize(byte[] data) {
        this.unusedVarySize = data;
        this.countLength();
        return this;
    }

    public RomExtensionStructureBuilder withBuildIdentifier(String data) {
        final ByteBuffer buffer = ByteBuffer.allocate(BUILD_IDENTIFIER_LEN);
        buffer.put(data.getBytes(StandardCharsets.UTF_8));
        this.buildIdentifier = buffer.array();
        return this;
    }

    private RomExtensionStructureBuilder countLength() {
        this.length = countCapacityWithoutSignature();
        return this;
    }

    public RomExtensionStructureBuilder sign(ISignBytes callback) {
        this.signature = callback.sign(getPayloadForSignature());
        return this;
    }

    @Override
    public RomExtensionStructureBuilder parse(ByteBufferSafe buffer) throws ParseStructureException {
        try {
            verifyMagic(buffer);
            length = convertInt(buffer.getInt(), ROM_EXT_LENGTH);
            buffer.get(unusedFixedSize);
            ediId = convertInt(buffer.getInt(), ROM_EXT_EDI_ID);
            unusedVarySize = new byte[calculateVarySize()];
            buffer.get(unusedVarySize);
            buffer.get(buildIdentifier);
            familyId = buffer.getByte();
            buffer.get(reserved);
            signature = buffer.getRemaining();
            if (signature.length > 0) {
                romExtSigBuilder = RomExtensionSignatureBuilder
                    .instance().withActor(getActor()).parse(signature);
            }
        } catch (BufferUnderflowException | BufferOverflowException | ByteBufferSafeException e) {
            throw new ParseStructureException("Failed to parse structure.", e);
        }
        return this;
    }

    @Override
    public RomExtensionStructure build() {
        final RomExtensionStructure structure = new RomExtensionStructure();
        structure.setMagic(convert(MAGIC, ROM_EXT_MAGIC));
        structure.setLength(convert(toBytes(this.length), ROM_EXT_LENGTH));
        structure.setUnusedFixedSize(unusedFixedSize);
        structure.setEdiId(convert(ediId, ROM_EXT_EDI_ID));
        structure.setUnusedVarySize(unusedVarySize);
        structure.setBuildIdentifier(buildIdentifier);
        structure.setFamilyId(new byte[]{familyId});
        structure.setReserved(reserved);
        structure.setSignature(signature);
        return structure;
    }

    private int countCapacityWithoutSignature() {
        int capacity = countBaseCapacity();
        capacity += unusedVarySize.length;
        return capacity;
    }

    private static int countBaseCapacity() {
        int capacity = 0;
        capacity += MAGIC_LEN;
        capacity += LENGTH_LEN;
        capacity += UNUSED_FIXED_SIZE_LEN;
        capacity += EDI_ID_LEN;
        capacity += BUILD_IDENTIFIER_LEN;
        capacity += FAMILY_ID_LEN;
        capacity += RESERVED_LEN;
        return capacity;
    }

    public String getBuildIdentifierString() {
        return new String(buildIdentifier, StandardCharsets.UTF_8).trim();
    }

    public byte[] getPayloadForSignature() {
        final EndiannessActor currentActor = getActor();
        withActor(FIRMWARE);

        final ByteBuffer buffer = ByteBuffer.allocate(countCapacityWithoutSignature());

        buffer.put(convert(MAGIC, ROM_EXT_MAGIC));
        buffer.put(convert(length, ROM_EXT_LENGTH));
        buffer.put(unusedFixedSize);
        buffer.put(convert(ediId, ROM_EXT_EDI_ID));
        buffer.put(unusedVarySize);
        buffer.put(buildIdentifier);
        buffer.put(familyId);
        buffer.put(reserved);

        final byte[] payload = buffer.array();
        withActor(currentActor);
        return payload;
    }

    public String calculateRomExtensionHash() {
        return CryptoUtils.generateFingerprint(getPayloadForSignature()).toUpperCase(Locale.ROOT);
    }

    private void verifyMagic(ByteBufferSafe buffer) throws ParseStructureException {
        final int magic = convertInt(buffer.getInt(), ROM_EXT_MAGIC);
        if (MAGIC != magic) {
            throw new ParseStructureException(String.format("Invalid magic number in Rom structure. "
                + "Expected: %s, Actual: %s.", toFormattedHex(MAGIC), toFormattedHex(magic)));
        }
    }

    private int calculateVarySize() {
        return length
            - MAGIC_LEN
            - LENGTH_LEN
            - UNUSED_FIXED_SIZE_LEN
            - EDI_ID_LEN
            - BUILD_IDENTIFIER_LEN
            - FAMILY_ID_LEN
            - RESERVED_LEN;
    }
}
