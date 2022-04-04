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

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.endianess.EndianessStructureFields;
import com.intel.bkp.core.endianess.EndianessStructureType;
import com.intel.bkp.core.endianess.maps.PsgCertificateEntryEndianessMapImpl;
import com.intel.bkp.core.interfaces.ISignBytes;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.PsgCancellation;
import com.intel.bkp.core.psgcertificate.model.PsgPermissions;
import com.intel.bkp.core.utils.ModifyBitsBuilder;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import lombok.Getter;
import org.apache.commons.lang3.ArrayUtils;

/**
 * Certificate entry in PSG format.
 *
 * <p>Builder must be initiated in proper order i.e. public key, permissions, cancellation, signature, sign data</p>
 */
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
@Getter
public class PsgCertificateEntryBuilder extends PsgDataBuilder<PsgCertificateEntryBuilder> {

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
    private PsgSignatureBuilder psgSignatureBuilder = new PsgSignatureBuilder();

    @Override
    public EndianessStructureType currentStructureMap() {
        return EndianessStructureType.PSG_CERT_ENTRY;
    }

    @Override
    public PsgCertificateEntryBuilder withActor(EndianessActor actor) {
        changeActor(actor);
        psgPublicKeyBuilder.withActor(getActor());
        psgSignatureBuilder.withActor(getActor());
        return this;
    }

    @Override
    protected void initStructureMap(EndianessStructureType currentStructureType, EndianessActor currentActor) {
        maps.put(currentStructureType, new PsgCertificateEntryEndianessMapImpl(currentActor));
    }

    private void setLengthOffset() {
        lengthOffset = ENTRY_BASIC_SIZE + dataLength + signatureLength;
    }

    private void setDataLength() {
        dataLength = (isPublicKeyEnabled() ? psgPublicKeyBuilder.totalLen() : 0);
    }

    private void setSignatureLength() {
        signatureLength = (isSignatureEnabled() ? psgSignatureBuilder.totalLen() : 0);
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

    public PsgCertificateEntryBuilder signData(ISignBytes signBytesCallback) {
        byte[] signed = signBytesCallback.sign(psgPublicKeyBuilder.withActor(EndianessActor.FIRMWARE).build().array());
        psgSignatureBuilder.signature(signed);
        return this;
    }

    public byte[] getPublicKeyXY() {
        return ArrayUtils.addAll(psgPublicKeyBuilder.getPointX(), psgPublicKeyBuilder.getPointY());
    }

    public PsgCertificateEntry build() throws PsgCertificateException {
        verifyPubKeyAndSignatureEnabled();

        PsgCertificateEntry certificateEntry = new PsgCertificateEntry();
        certificateEntry.setMagic(convert(PUBLIC_KEY_ENTRY_MAGIC, EndianessStructureFields.PSG_CERT_MAGIC));
        certificateEntry.setLengthOffset(convert(lengthOffset, EndianessStructureFields.PSG_CERT_LENGTH_OFFSET));
        certificateEntry.setDataLength(convert(dataLength, EndianessStructureFields.PSG_CERT_DATA_LEN));
        certificateEntry.setSignatureLength(convert(signatureLength, EndianessStructureFields.PSG_CERT_SIG_LEN));
        certificateEntry.setShaLength(convert(shaLength, EndianessStructureFields.PSG_CERT_SHA_LEN));
        certificateEntry.setReserved(convert(reserved, EndianessStructureFields.PSG_CERT_RESERVED));
        certificateEntry.setPsgPublicKey(psgPublicKeyBuilder.withActor(getActor()).build().array());
        certificateEntry.setPsgSignature(psgSignatureBuilder.withActor(getActor()).build().array());

        return certificateEntry;
    }

    public PsgCertificateEntryBuilder parse(byte[] certificateContent) throws PsgCertificateException {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(certificateContent);
        try {
            parsePsgMetadata(buffer);
            parsePsgPublicKey(buffer);
            parseSignature(buffer);
            return this;
        } catch (ByteBufferSafeException e) {
            throw new PsgCertificateException("Invalid buffer during parsing entry", e);
        } catch (PsgInvalidSignatureException e) {
            throw new PsgCertificateException("Invalid signature during parsing entry", e);
        }
    }

    private void parsePsgMetadata(ByteBufferSafe buffer) throws PsgCertificateException {
        PsgCertificateHelper.verifyEntryMagic(convertInt(buffer.getInt(), EndianessStructureFields.PSG_CERT_MAGIC));

        lengthOffset = convertInt(buffer.getInt(), EndianessStructureFields.PSG_CERT_LENGTH_OFFSET);
        dataLength = convertInt(buffer.getInt(), EndianessStructureFields.PSG_CERT_DATA_LEN);
        signatureLength = convertInt(buffer.getInt(), EndianessStructureFields.PSG_CERT_SIG_LEN);
        shaLength = convertInt(buffer.getInt(), EndianessStructureFields.PSG_CERT_SHA_LEN);
        reserved = convertInt(buffer.getInt(), EndianessStructureFields.PSG_CERT_RESERVED);
    }

    private void parsePsgPublicKey(ByteBufferSafe buffer) throws PsgCertificateException {
        psgPublicKeyBuilder = new PsgPublicKeyBuilder().withActor(getActor()).parse(buffer);
    }

    private void parseSignature(ByteBufferSafe buffer) throws PsgInvalidSignatureException {
        if (signatureLength > 0) {
            psgSignatureBuilder = new PsgSignatureBuilder().withActor(getActor()).parse(buffer);
        }
    }

    private void verifyPubKeyAndSignatureEnabled() throws PsgCertificateException {
        if (!isPublicKeyEnabled()) {
            throw new PsgCertificateException("PsgPublicKey is not set");
        }

        if (!isSignatureEnabled()) {
            throw new PsgCertificateException("PsgSignature is not set");
        }
    }

    private boolean isPublicKeyEnabled() {
        return psgPublicKeyBuilder != null;
    }

    private boolean isSignatureEnabled() {
        return psgSignatureBuilder != null;
    }
}
