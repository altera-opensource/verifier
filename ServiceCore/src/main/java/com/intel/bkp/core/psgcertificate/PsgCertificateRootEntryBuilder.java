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
import com.intel.bkp.core.endianness.maps.PsgCertificateRootEntryEndiannessMapImpl;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgPubKeyException;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgRootCertMagic;
import com.intel.bkp.core.psgcertificate.model.PsgRootHashType;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import lombok.Getter;

import java.util.Optional;

/**
 * Root certificate entry in PSG format.
 *
 * <p>Builder must be initiated in proper order i.e. public key, permissions, cancellation</p>
 */
@Getter
public class PsgCertificateRootEntryBuilder extends EndiannessBuilder<PsgCertificateRootEntryBuilder> {

    private static final int ENTRY_BASIC_SIZE = 8 * Integer.BYTES; // 8 fields

    private int magic = PsgRootCertMagic.SINGLE.getValue();
    private int lengthOffset = ENTRY_BASIC_SIZE;
    private int dataLength = 0;
    private int signatureLength = 0;
    private int shaLength = 0;
    private PsgRootHashType rootHashType = PsgRootHashType.INTEL;
    private int msbOfPubKey = 0;
    private int reserved = 0;
    private PsgPublicKeyBuilder psgPublicKeyBuilder = new PsgPublicKeyBuilder();

    public PsgCertificateRootEntryBuilder() {
        super(EndiannessStructureType.PSG_CERT_ROOT_ENTRY);
    }

    @Override
    public PsgCertificateRootEntryBuilder withActor(EndiannessActor actor) {
        super.withActor(actor);
        Optional.ofNullable(psgPublicKeyBuilder).ifPresent(item -> item.withActor(getActor()));
        return this;
    }

    @Override
    protected PsgCertificateRootEntryBuilder self() {
        return this;
    }

    @Override
    protected void initStructureMap(EndiannessStructureType currentStructureType, EndiannessActor currentActor) {
        maps.put(currentStructureType, new PsgCertificateRootEntryEndiannessMapImpl(currentActor));
    }

    private void setLengthOffset() {
        lengthOffset = ENTRY_BASIC_SIZE + dataLength + signatureLength;
    }

    private void setDataLength() {
        dataLength = (isPublicKeyEnabled() ? psgPublicKeyBuilder.totalLen() : 0);
    }

    private boolean isPublicKeyEnabled() {
        return psgPublicKeyBuilder != null;
    }

    public PsgCertificateRootEntryBuilder asMultiRoot() {
        this.magic = PsgRootCertMagic.MULTI.getValue();
        return this;
    }

    public PsgCertificateRootEntryBuilder rootHashType(PsgRootHashType type) {
        this.rootHashType = type;
        return this;
    }

    public PsgCertificateRootEntryBuilder publicKey(PsgPublicKeyBuilder psgPublicKeyBuilder) {
        this.psgPublicKeyBuilder = psgPublicKeyBuilder;
        setupMSBforPubKey();
        setDataLength();
        setLengthOffset();
        return this;
    }

    public PsgCertificateRootEntry build() throws PsgCertificateException {
        verifyPubKeyEnabled();

        PsgCertificateRootEntry certificateEntry = new PsgCertificateRootEntry();
        certificateEntry.setMagic(convert(magic, EndiannessStructureFields.PSG_CERT_ROOT_MAGIC));
        certificateEntry.setLengthOffset(convert(lengthOffset, EndiannessStructureFields.PSG_CERT_ROOT_LENGTH_OFFSET));
        certificateEntry.setDataLength(convert(dataLength, EndiannessStructureFields.PSG_CERT_ROOT_DATA_LEN));
        certificateEntry.setSignatureLength(convert(signatureLength, EndiannessStructureFields.PSG_CERT_ROOT_SIG_LEN));
        certificateEntry.setShaLength(convert(shaLength, EndiannessStructureFields.PSG_CERT_ROOT_SHA_LEN));
        certificateEntry.setRootHashType(convert(rootHashType.ordinal(),
            EndiannessStructureFields.PSG_CERT_ROOT_ROOT_HASH_TYPE));
        certificateEntry.setMsbOfPubKey(convert(msbOfPubKey, EndiannessStructureFields.PSG_CERT_ROOT_MSB_OF_PUB_KEY));
        certificateEntry.setReserved(convert(reserved, EndiannessStructureFields.PSG_CERT_ROOT_RESERVED));
        certificateEntry.setPsgPublicKey(psgPublicKeyBuilder.withActor(getActor()).build().array());

        return certificateEntry;
    }

    private void setupMSBforPubKey() {
        final CurvePoint curvePoint = psgPublicKeyBuilder.getCurvePoint();
        byte[] combinedPubKey = curvePoint.getAlignedDataToSize();
        final PsgCurveType psgCurveType = PsgCurveType.fromCurveSpec(curvePoint.getCurveSpec());

        msbOfPubKey = switch (psgCurveType) {
            case SECP256R1 -> CryptoUtils.getIntForSha256(combinedPubKey);
            case SECP384R1 -> CryptoUtils.getIntForSha384(combinedPubKey);
        };
    }

    public PsgCertificateRootEntryBuilder parse(byte[] certificateContent) throws PsgCertificateException {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(certificateContent);
        try {
            parsePsgMetadata(buffer);
            parsePsgPublicKey(buffer);
            return this;
        } catch (ByteBufferSafeException | PsgPubKeyException e) {
            throw new PsgCertificateException("Invalid buffer during parsing entry", e);
        }
    }

    private void parsePsgMetadata(ByteBufferSafe buffer) throws PsgCertificateException {
        final int magicTmp = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_CERT_ROOT_MAGIC);
        PsgCertificateHelper.verifyRootEntryMagic(magicTmp);

        magic = magicTmp;
        lengthOffset = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_CERT_ROOT_LENGTH_OFFSET);
        dataLength = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_CERT_ROOT_DATA_LEN);
        signatureLength = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_CERT_ROOT_SIG_LEN);
        shaLength = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_CERT_ROOT_SHA_LEN);
        rootHashType = PsgRootHashType.fromOrdinal(convertInt(buffer.getInt(),
            EndiannessStructureFields.PSG_CERT_ROOT_ROOT_HASH_TYPE));
        msbOfPubKey = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_CERT_ROOT_MSB_OF_PUB_KEY);
        reserved = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_CERT_ROOT_RESERVED);
    }

    private void parsePsgPublicKey(ByteBufferSafe buffer) throws PsgPubKeyException {
        psgPublicKeyBuilder = new PsgPublicKeyBuilder().withActor(getActor()).parse(buffer);
    }

    private void verifyPubKeyEnabled() throws PsgCertificateException {
        if (!isPublicKeyEnabled()) {
            throw new PsgCertificateException("PsgPublicKey is not set");
        }
    }
}
