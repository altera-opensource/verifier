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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.endianness.StructureType;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.interfaces.ISignBytes;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.model.PsgCancellation;
import com.intel.bkp.core.psgcertificate.model.PsgPermissions;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.core.utils.ModifyBitsBuilder;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import lombok.Getter;

import java.util.Optional;

import static com.intel.bkp.core.endianness.StructureField.PSG_CERT_DATA_LEN;
import static com.intel.bkp.core.endianness.StructureField.PSG_CERT_LENGTH_OFFSET;
import static com.intel.bkp.core.endianness.StructureField.PSG_CERT_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_CERT_RESERVED;
import static com.intel.bkp.core.endianness.StructureField.PSG_CERT_SHA_LEN;
import static com.intel.bkp.core.endianness.StructureField.PSG_CERT_SIG_LEN;

/**
 * Certificate entry in PSG format.
 *
 * <p>Builder must be initiated in proper order i.e. public key, permissions, cancellation, signature, sign data</p>
 */
@Getter
public class PsgCertificateEntryBuilder extends StructureBuilder<PsgCertificateEntryBuilder, PsgCertificateEntry> {

    public static final int PUBLIC_KEY_ENTRY_MAGIC = 0x92540917;

    static final int ENTRY_BASIC_SIZE = 6 * Integer.BYTES; // 6 fields
    private static final int DATA_LENGTH_LEN = Integer.BYTES;
    private static final int SHA_LENGTH_LEN = Integer.BYTES;
    private static final int RESERVED_LEN = Integer.BYTES;

    private int lengthOffset = ENTRY_BASIC_SIZE;
    private int dataLength = 0;
    private int signatureLength = 0;
    private int shaLength = 0;
    private int reserved = 0;
    private PsgPublicKeyBuilder psgPublicKeyBuilder = new PsgPublicKeyBuilder();
    private PsgSignatureBuilder psgSignatureBuilder = PsgSignatureBuilder.empty(PsgSignatureCurveType.SECP384R1);

    public PsgCertificateEntryBuilder() {
        super(StructureType.PSG_CERT_ENTRY);
    }

    @Override
    public PsgCertificateEntryBuilder withActor(EndiannessActor actor) {
        super.withActor(actor);
        Optional.ofNullable(psgPublicKeyBuilder).ifPresent(item -> item.withActor(getActor()));
        Optional.ofNullable(psgSignatureBuilder).ifPresent(item -> item.withActor(getActor()));
        return this;
    }

    @Override
    public PsgCertificateEntryBuilder self() {
        return this;
    }

    private void setLengthOffset() {
        lengthOffset = ENTRY_BASIC_SIZE + dataLength + signatureLength;
    }

    private void setDataLength() {
        dataLength = (isPublicKeyEnabled() ? psgPublicKeyBuilder.totalLen() : 0);
    }

    private void setSignatureLength() {
        signatureLength = (isSignatureEnabled() ? psgSignatureBuilder.getTotalSignatureSize() : 0);
    }

    public PsgCertificateEntryBuilder publicKey(PsgPublicKeyBuilder psgPublicKeyBuilder) {
        this.psgPublicKeyBuilder = psgPublicKeyBuilder;
        setDataLength();
        setLengthOffset();
        return this;
    }

    public PsgCertificateEntryBuilder withBkpPermissions() {
        final int permissions = ModifyBitsBuilder.fromNone().set(PsgPermissions.SIGN_BKP_DH.getBitPosition()).build();
        return withPermissions(permissions);
    }

    public PsgCertificateEntryBuilder withPermissions(final int permissions) {
        psgPublicKeyBuilder.permissions(permissions);
        return this;
    }

    public PsgCertificateEntryBuilder withNoCancellationId() {
        final int cancellation = PsgCancellation.CANCELLATION_ID_MIN;
        psgPublicKeyBuilder.cancellation(cancellation);
        return this;
    }

    public PsgCertificateEntryBuilder withSignature(PsgSignatureBuilder psgSignatureBuilder) {
        this.psgSignatureBuilder = psgSignatureBuilder;
        setSignatureLength();
        setLengthOffset();
        return this;
    }

    public PsgCertificateEntryBuilder signData(ISignBytes signBytesCallback, PsgSignatureCurveType signatureType) {
        byte[] signed = signBytesCallback.sign(psgPublicKeyBuilder.withActor(EndiannessActor.FIRMWARE).build().array());
        psgSignatureBuilder.signature(signed, signatureType);
        return this;
    }

    public byte[] getPublicKeyXY() {
        return psgPublicKeyBuilder.getCurvePoint().getAlignedDataToSize();
    }

    @Override
    public PsgCertificateEntry build() {
        PsgCertificateEntry certificateEntry = new PsgCertificateEntry();
        certificateEntry.setMagic(convert(PUBLIC_KEY_ENTRY_MAGIC, PSG_CERT_MAGIC));
        certificateEntry.setLengthOffset(convert(lengthOffset, PSG_CERT_LENGTH_OFFSET));
        certificateEntry.setDataLength(convert(dataLength, PSG_CERT_DATA_LEN));
        certificateEntry.setSignatureLength(convert(signatureLength, PSG_CERT_SIG_LEN));
        certificateEntry.setShaLength(convert(shaLength, PSG_CERT_SHA_LEN));
        certificateEntry.setReserved(convert(reserved, PSG_CERT_RESERVED));
        certificateEntry.setPsgPublicKey(psgPublicKeyBuilder.withActor(getActor()).build().array());
        certificateEntry.setPsgSignature(psgSignatureBuilder.withActor(getActor()).build().array());

        return certificateEntry;
    }

    @Override
    public PsgCertificateEntryBuilder parse(ByteBufferSafe buffer) throws ParseStructureException {
        try {
            parsePsgMetadata(buffer);
            parsePsgPublicKey(buffer);
            parseSignature(buffer);
            return this;
        } catch (ByteBufferSafeException | PsgCertificateException e) {
            throw new ParseStructureException("Invalid buffer during parsing entry", e);
        }
    }

    private void parsePsgMetadata(ByteBufferSafe buffer) throws PsgCertificateException {
        PsgCertificateHelper.verifyEntryMagic(convertInt(buffer.getInt(), PSG_CERT_MAGIC));

        lengthOffset = convertInt(buffer.getInt(), PSG_CERT_LENGTH_OFFSET);
        dataLength = convertInt(buffer.getInt(), PSG_CERT_DATA_LEN);
        signatureLength = convertInt(buffer.getInt(), PSG_CERT_SIG_LEN);
        shaLength = convertInt(buffer.getInt(), PSG_CERT_SHA_LEN);
        reserved = convertInt(buffer.getInt(), PSG_CERT_RESERVED);
    }

    private void parsePsgPublicKey(ByteBufferSafe buffer) {
        psgPublicKeyBuilder = new PsgPublicKeyBuilder().withActor(getActor()).parse(buffer);
    }

    private void parseSignature(ByteBufferSafe buffer) {
        if (signatureLength > 0) {
            psgSignatureBuilder = new PsgSignatureBuilder().withActor(getActor()).parse(buffer);
        }
    }

    private boolean isPublicKeyEnabled() {
        return psgPublicKeyBuilder != null;
    }

    private boolean isSignatureEnabled() {
        return psgSignatureBuilder != null;
    }
}
