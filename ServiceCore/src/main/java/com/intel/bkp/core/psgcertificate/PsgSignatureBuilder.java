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
import com.intel.bkp.core.endianess.maps.PsgSignatureEndianessMapImpl;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.PsgSignature;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.PaddingUtils;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PsgSignatureBuilder extends PsgDataBuilder<PsgSignatureBuilder> {

    private static final int SIGNATURE_MAGIC = 0x74881520;

    private PsgSignatureCurveType signatureType = PsgSignatureCurveType.SECP384R1;
    private int sizeR = 0;
    private int sizeS = 0;
    private byte[] signatureR = new byte[signatureType.getSize()];
    private byte[] signatureS = new byte[signatureType.getSize()];

    @Override
    public EndianessStructureType currentStructureMap() {
        return EndianessStructureType.PSG_SIGNATURE;
    }

    @Override
    public PsgSignatureBuilder withActor(EndianessActor actor) {
        changeActor(actor);
        return this;
    }

    @Override
    protected void initStructureMap(EndianessStructureType currentStructureType, EndianessActor currentActor) {
        maps.put(currentStructureType, new PsgSignatureEndianessMapImpl(currentActor));
    }

    public PsgSignatureBuilder signatureType(PsgSignatureCurveType signatureType) {
        this.signatureType = signatureType;
        initializeRS();
        return this;
    }

    public PsgSignatureBuilder signature(byte[] signedData) {
        prepareSignature(signedData);
        return this;
    }

    public int totalLen() {
        return PsgSignatureHelper.getTotalSignatureSize(signatureType);
    }

    public PsgSignature build() {
        PsgSignature psgSignature = new PsgSignature();
        psgSignature.setSignatureMagic(convert(SIGNATURE_MAGIC, EndianessStructureFields.PSG_SIG_MAGIC));
        psgSignature.setSizeR(convert(sizeR, EndianessStructureFields.PSG_SIG_SIZE_R));
        psgSignature.setSizeS(convert(sizeS, EndianessStructureFields.PSG_SIG_SIZE_S));
        psgSignature.setSignatureHashMagic(convert(signatureType.getMagic(),
            EndianessStructureFields.PSG_SIG_HASH_MAGIC));
        psgSignature.setSignatureR(convert(signatureR, EndianessStructureFields.PSG_SIG_R));
        psgSignature.setSignatureS(convert(signatureS, EndianessStructureFields.PSG_SIG_S));
        return psgSignature;
    }

    public PsgSignatureBuilder parse(byte[] sig) throws PsgInvalidSignatureException {
        return parse(ByteBufferSafe.wrap(sig));
    }

    public PsgSignatureBuilder parse(ByteBufferSafe buffer) throws PsgInvalidSignatureException {
        PsgSignatureHelper.verifySignatureMagic(convertInt(buffer.getInt(),
            EndianessStructureFields.PSG_SIG_MAGIC));

        sizeR = convertInt(buffer.getInt(), EndianessStructureFields.PSG_SIG_SIZE_R);
        sizeS = convertInt(buffer.getInt(), EndianessStructureFields.PSG_SIG_SIZE_S);

        signatureType = PsgSignatureHelper.parseSignatureType(convertInt(buffer.getInt(),
            EndianessStructureFields.PSG_SIG_HASH_MAGIC));

        signatureR = buffer.arrayFromInt(signatureType.getSize());
        buffer.get(signatureR);
        signatureR = convert(signatureR, EndianessStructureFields.PSG_SIG_R);
        signatureS = buffer.arrayFromInt(signatureType.getSize());
        buffer.get(signatureS);
        signatureS = convert(signatureS, EndianessStructureFields.PSG_SIG_S);
        return this;
    }

    private void initializeRS() {
        signatureR = new byte[signatureType.getSize()];
        signatureS = new byte[signatureType.getSize()];
    }

    private void prepareSignature(byte[] signedData) {
        ByteBufferSafe.wrap(removePadding(signatureType, PsgSignatureHelper.extractR(signedData))).getAll(signatureR);
        ByteBufferSafe.wrap(removePadding(signatureType, PsgSignatureHelper.extractS(signedData))).getAll(signatureS);
    }

    private byte[] removePadding(PsgSignatureCurveType curveType, byte[] arr) {
        return PaddingUtils.alignTo(arr, curveType.getSize());
    }
}
