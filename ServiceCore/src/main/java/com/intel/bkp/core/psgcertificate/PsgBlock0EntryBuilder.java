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
import com.intel.bkp.core.endianness.EndiannessStructureFields;
import com.intel.bkp.core.endianness.EndiannessStructureType;
import com.intel.bkp.core.endianness.maps.PsgBlock0EntryEndiannessMapImpl;
import com.intel.bkp.core.psgcertificate.exceptions.PsgBlock0EntryException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.PsgBlock0Entry;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;

import java.util.Optional;

import static com.intel.bkp.utils.HexConverter.toFormattedHex;

public class PsgBlock0EntryBuilder extends EndiannessBuilder<PsgBlock0EntryBuilder> {

    public static final int BLOCK0_ENTRY_MAGIC = 0x15364367;

    private static final int ENTRY_BASIC_SIZE = 6 * Integer.BYTES; // 6 fields with 4 bytes
    private static final PsgSignatureCurveType SIGNATURE_CURVE_TYPE = PsgSignatureCurveType.SECP384R1;
    private static final int SIGNATURE_SIZE = PsgSignatureBuilder.getTotalSignatureSize(SIGNATURE_CURVE_TYPE);

    public static int predictFinalLength() {
        return ENTRY_BASIC_SIZE + SIGNATURE_SIZE;
    }

    private int lengthOffset = ENTRY_BASIC_SIZE + SIGNATURE_SIZE;
    private int dataLength = 0;
    private int signatureLength = SIGNATURE_SIZE;
    private int shaLength = 0;
    private int reserved = 0;
    private PsgSignatureBuilder psgSignatureBuilder = PsgSignatureBuilder
        .empty(PsgSignatureCurveType.SECP384R1)
        .withActor(EndiannessActor.SERVICE);


    public PsgBlock0EntryBuilder() {
        super(EndiannessStructureType.PSG_BLOCK_0_ENTRY);
    }

    @Override
    public PsgBlock0EntryBuilder withActor(EndiannessActor actor) {
        super.withActor(actor);
        Optional.ofNullable(psgSignatureBuilder).ifPresent(item -> item.withActor(getActor()));
        return this;
    }

    @Override
    protected PsgBlock0EntryBuilder self() {
        return this;
    }

    @Override
    protected void initStructureMap(EndiannessStructureType currentStructureType, EndiannessActor currentActor) {
        maps.put(currentStructureType, new PsgBlock0EntryEndiannessMapImpl(currentActor));
    }

    public PsgBlock0EntryBuilder signature(byte[] signedData, PsgSignatureCurveType signatureType) {
        psgSignatureBuilder.signature(signedData, signatureType);
        return this;
    }

    public PsgBlock0Entry build() {
        PsgBlock0Entry psgBlock0Entry = new PsgBlock0Entry();
        psgBlock0Entry.setMagic(convert(BLOCK0_ENTRY_MAGIC, EndiannessStructureFields.BLOCK0_ENTRY_MAGIC));
        psgBlock0Entry.setLengthOffset(convert(lengthOffset, EndiannessStructureFields.BLOCK0_LENGTH_OFFSET));
        psgBlock0Entry.setDataLength(convert(dataLength, EndiannessStructureFields.BLOCK0_DATA_LEN));
        psgBlock0Entry.setSignatureLength(convert(signatureLength, EndiannessStructureFields.BLOCK0_SIG_LEN));
        psgBlock0Entry.setShaLength(convert(shaLength, EndiannessStructureFields.BLOCK0_SHA_LEN));
        psgBlock0Entry.setReserved(convert(reserved, EndiannessStructureFields.BLOCK0_RESERVED));
        psgBlock0Entry.setPsgSignature(psgSignatureBuilder.withActor(getActor()).build().array());

        return psgBlock0Entry;
    }

    public PsgBlock0EntryBuilder parse(byte[] content) throws PsgBlock0EntryException {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(content);
        try {
            int entryMagic = convertInt(buffer.getInt(), EndiannessStructureFields.BLOCK0_ENTRY_MAGIC);
            if (BLOCK0_ENTRY_MAGIC != entryMagic) {
                throw new PsgBlock0EntryException(
                    String.format("Invalid magic number in Block0 Entry. Expected: %s, Actual: %s.",
                        toFormattedHex(BLOCK0_ENTRY_MAGIC), toFormattedHex(entryMagic)));
            }

            lengthOffset = convertInt(buffer.getInt(), EndiannessStructureFields.BLOCK0_LENGTH_OFFSET);
            dataLength = convertInt(buffer.getInt(), EndiannessStructureFields.BLOCK0_DATA_LEN);
            signatureLength = convertInt(buffer.getInt(), EndiannessStructureFields.BLOCK0_SIG_LEN);
            shaLength = convertInt(buffer.getInt(), EndiannessStructureFields.BLOCK0_SHA_LEN);
            reserved = convertInt(buffer.getInt(), EndiannessStructureFields.BLOCK0_RESERVED);
            psgSignatureBuilder.withActor(getActor()).parse(buffer);
            return this;
        } catch (ByteBufferSafeException | PsgInvalidSignatureException e) {
            throw new PsgBlock0EntryException("Invalid buffer during parsing Block0 Entry.", e);
        }
    }
}
