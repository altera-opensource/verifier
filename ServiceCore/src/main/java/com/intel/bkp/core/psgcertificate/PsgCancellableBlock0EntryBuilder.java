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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.EndiannessBuilder;
import com.intel.bkp.core.endianness.EndiannessStructureType;
import com.intel.bkp.core.endianness.maps.PsgCancellableBlock0EntryEndiannessMapImpl;
import com.intel.bkp.core.psgcertificate.exceptions.PsgBlock0EntryException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.PsgCancellableBlock0Entry;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteConverter;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import lombok.Getter;
import org.apache.commons.codec.digest.DigestUtils;

import java.nio.ByteBuffer;
import java.util.Optional;

import static com.intel.bkp.core.endianness.EndiannessStructureFields.CANCELLABLE_BLOCK0_CANCELLATION_ID;
import static com.intel.bkp.core.endianness.EndiannessStructureFields.CANCELLABLE_BLOCK0_DATA_LEN;
import static com.intel.bkp.core.endianness.EndiannessStructureFields.CANCELLABLE_BLOCK0_ENTRY_MAGIC;
import static com.intel.bkp.core.endianness.EndiannessStructureFields.CANCELLABLE_BLOCK0_LENGTH_OFFSET;
import static com.intel.bkp.core.endianness.EndiannessStructureFields.CANCELLABLE_BLOCK0_META_MAGIC;
import static com.intel.bkp.core.endianness.EndiannessStructureFields.CANCELLABLE_BLOCK0_SHA_LEN;
import static com.intel.bkp.core.endianness.EndiannessStructureFields.CANCELLABLE_BLOCK0_SIG_LEN;
import static com.intel.bkp.utils.HexConverter.toFormattedHex;

public class PsgCancellableBlock0EntryBuilder extends EndiannessBuilder<PsgCancellableBlock0EntryBuilder> {

    public static final int MAGIC = 0x65495853;
    public static final int METADATA_MAGIC = 0x71050792;

    private static final int ENTRY_BASIC_SIZE = 8 * Integer.BYTES; // 8 fields with 4 bytes
    private static final PsgSignatureCurveType SIGNATURE_CURVE_TYPE = PsgSignatureCurveType.SECP384R1;
    private static final int SIGNATURE_SIZE = PsgSignatureBuilder.getTotalSignatureSize(SIGNATURE_CURVE_TYPE);

    private int lengthOffset = ENTRY_BASIC_SIZE + SIGNATURE_SIZE;
    private int dataLength = 0;
    private int signatureLength = SIGNATURE_SIZE;
    private int shaLength = 0;
    private int reserved = 0;
    private int cancellationId = 0;
    @Getter
    private final PsgSignatureBuilder psgSignatureBuilder = PsgSignatureBuilder
        .empty(PsgSignatureCurveType.SECP384R1)
        .withActor(EndiannessActor.SERVICE);

    public PsgCancellableBlock0EntryBuilder() {
        super(EndiannessStructureType.PSG_CANCELLABLE_BLOCK0_ENTRY);
    }

    @Override
    public PsgCancellableBlock0EntryBuilder withActor(EndiannessActor actor) {
        super.withActor(actor);
        Optional.ofNullable(psgSignatureBuilder).ifPresent(item -> item.withActor(getActor()));
        return this;
    }

    @Override
    protected PsgCancellableBlock0EntryBuilder self() {
        return this;
    }

    @Override
    protected void initStructureMap(EndiannessStructureType currentStructureType, EndiannessActor currentActor) {
        maps.put(currentStructureType, new PsgCancellableBlock0EntryEndiannessMapImpl(currentActor));
    }

    public PsgCancellableBlock0EntryBuilder signature(byte[] signedData, PsgSignatureCurveType signatureType) {
        psgSignatureBuilder.signature(signedData, signatureType);
        return this;
    }

    public PsgCancellableBlock0Entry build() {
        final PsgCancellableBlock0Entry entry = new PsgCancellableBlock0Entry();
        entry.setMagic(convert(MAGIC, CANCELLABLE_BLOCK0_ENTRY_MAGIC));
        entry.setLengthOffset(convert(lengthOffset, CANCELLABLE_BLOCK0_LENGTH_OFFSET));
        entry.setDataLength(convert(dataLength, CANCELLABLE_BLOCK0_DATA_LEN));
        entry.setSignatureLength(convert(signatureLength, CANCELLABLE_BLOCK0_SIG_LEN));
        entry.setShaLength(convert(shaLength, CANCELLABLE_BLOCK0_SHA_LEN));
        entry.setReserved(ByteConverter.toBytes(reserved));
        entry.setBlock0MetaMagic(convert(METADATA_MAGIC, CANCELLABLE_BLOCK0_META_MAGIC));
        entry.setCancellationId(convert(cancellationId, CANCELLABLE_BLOCK0_CANCELLATION_ID));
        entry.setPsgSignature(psgSignatureBuilder.withActor(getActor()).build().array());
        return entry;
    }

    public PsgCancellableBlock0EntryBuilder parse(byte[] content) throws PsgBlock0EntryException {
        final ByteBufferSafe buffer = ByteBufferSafe.wrap(content);
        try {
            verifyMagic(buffer);
            lengthOffset = convertInt(buffer.getInt(), CANCELLABLE_BLOCK0_LENGTH_OFFSET);
            dataLength = convertInt(buffer.getInt(), CANCELLABLE_BLOCK0_DATA_LEN);
            signatureLength = convertInt(buffer.getInt(), CANCELLABLE_BLOCK0_SIG_LEN);
            shaLength = convertInt(buffer.getInt(), CANCELLABLE_BLOCK0_SHA_LEN);
            reserved = buffer.getInt();
            verifyMetadataMagic(buffer);
            cancellationId = convertInt(buffer.getInt(), CANCELLABLE_BLOCK0_CANCELLATION_ID);
            psgSignatureBuilder.withActor(getActor()).parse(buffer);
            return this;
        } catch (ByteBufferSafeException | PsgInvalidSignatureException e) {
            throw new PsgBlock0EntryException("Invalid buffer during parsing CancellableBlock0 Entry.", e);
        }
    }

    public byte[] getCustomPayloadForSignature(byte[] payloadForSignature) {
        final EndiannessActor currentActor = getActor();
        withActor(EndiannessActor.FIRMWARE);
        final PsgCancellableBlock0Entry cancellableBlock0Entry = build();
        withActor(currentActor);
        return customPayloadForSignature(cancellableBlock0Entry, payloadForSignature);
    }

    /**
     * Signature is in custom format: Block0MetadataMagic + CancellationId + SHA384 (payloadForSignature).
     * Example: 92070571ffffffff + DigestUtils.sha384Hex(payloadForSignature)
     *
     * @param entry Entry in Firmware endianness
     * @param payloadForSignature Payload of signature
     *
     * @return custom Signature
     */
    public static byte[] customPayloadForSignature(PsgCancellableBlock0Entry entry, byte[] payloadForSignature) {
        final byte[] sha384Hash = DigestUtils.sha384(payloadForSignature);

        final int capacity = entry.getBlock0MetaMagic().length
            + entry.getCancellationId().length
            + sha384Hash.length;

        ByteBuffer buffer = ByteBuffer.allocate(capacity);
        buffer.put(entry.getBlock0MetaMagic());
        buffer.put(entry.getCancellationId());
        buffer.put(sha384Hash);
        return buffer.array();
    }

    private void verifyMagic(ByteBufferSafe buffer) throws PsgBlock0EntryException {
        final int entryMagic = convertInt(buffer.getInt(), CANCELLABLE_BLOCK0_ENTRY_MAGIC);
        if (MAGIC != entryMagic) {
            throw new PsgBlock0EntryException(
                String.format("Invalid magic number in CancellableBlock0 Entry. Expected: %s, Actual: %s.",
                    toFormattedHex(MAGIC), toFormattedHex(entryMagic)));
        }
    }

    private void verifyMetadataMagic(ByteBufferSafe buffer) throws PsgBlock0EntryException {
        final int entryMetaDataMagic = convertInt(buffer.getInt(), CANCELLABLE_BLOCK0_META_MAGIC);
        if (METADATA_MAGIC != entryMetaDataMagic) {
            throw new PsgBlock0EntryException(
                String.format("Invalid meta data magic number in CancellableBlock0 Entry. Expected: %s, Actual: %s.",
                    toFormattedHex(METADATA_MAGIC), toFormattedHex(entryMetaDataMagic)));
        }
    }

    public PsgCancellableBlock0EntryBuilder withDataToSign(byte[] dataToSign) {
        return null;
    }
}
