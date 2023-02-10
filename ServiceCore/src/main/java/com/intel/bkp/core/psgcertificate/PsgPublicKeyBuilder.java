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
import com.intel.bkp.core.endianness.maps.PsgPublicKeyEndiannessMapImpl;
import com.intel.bkp.core.psgcertificate.exceptions.PsgPubKeyException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgPublicKeyBuilderException;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKey;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.utils.ModifyBitsBuilder;
import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.Getter;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static com.intel.bkp.utils.HexConverter.fromHex;

@Getter
public class PsgPublicKeyBuilder extends EndiannessBuilder<PsgPublicKeyBuilder> {

    private PsgPublicKeyMagic magic = PsgPublicKeyMagic.M1_MAGIC;
    private static final int PUBKEY_METADATA_SIZE = 6 * Integer.BYTES;
    private int publicKeyPermissions = ModifyBitsBuilder.fromNone().build();
    private int publicKeyCancellation = ModifyBitsBuilder.fromAll().build();
    private int sizeX = 0;
    private int sizeY = 0;
    private CurvePoint curvePoint;

    public PsgPublicKeyBuilder() {
        super(EndiannessStructureType.PSG_PUBLIC_KEY);
    }

    @Override
    protected PsgPublicKeyBuilder self() {
        return this;
    }

    @Override
    protected void initStructureMap(EndiannessStructureType currentStructureType, EndiannessActor currentActor) {
        maps.put(currentStructureType, new PsgPublicKeyEndiannessMapImpl(currentActor));
    }

    public int totalLen() {
        return (2 * curvePoint.getCurveSpec().getSize()) + PUBKEY_METADATA_SIZE;
    }

    public PsgPublicKeyBuilder magic(PsgPublicKeyMagic magic) {
        this.magic = magic;
        return this;
    }

    public PsgPublicKeyBuilder permissions(int permissions) {
        this.publicKeyPermissions = permissions;
        return this;
    }

    public PsgPublicKeyBuilder cancellation(int cancellation) {
        this.publicKeyCancellation = cancellation;
        return this;
    }

    public PsgPublicKeyBuilder publicKey(byte[] encodedPublicKey, PsgCurveType psgCurveType)
        throws PsgPublicKeyBuilderException {
        try {
            this.curvePoint = CurvePoint.fromPubKeyEncoded(encodedPublicKey, psgCurveType.getCurveSpec());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new PsgPublicKeyBuilderException();
        }
        return this;
    }

    public PsgPublicKeyBuilder publicKey(PublicKey publicKey, PsgCurveType psgCurveType) {
        this.curvePoint = CurvePoint.from(publicKey, psgCurveType.getCurveSpec());
        return this;
    }

    public PsgPublicKeyBuilder curvePoint(CurvePoint curvePoint) {
        this.curvePoint = curvePoint;
        return this;
    }

    public PsgPublicKeyBuilder publicKeyPointXY(byte[] publicKeyXY, PsgCurveType psgCurveType) {
        this.curvePoint = CurvePoint.fromPubKey(publicKeyXY, psgCurveType.getCurveSpec());
        return this;
    }

    public PsgPublicKey build() {
        PsgPublicKey psgPublicKey = new PsgPublicKey();
        psgPublicKey.setMagic(convert(magic.getValue(), EndiannessStructureFields.PSG_PUB_KEY_MAGIC));
        psgPublicKey.setSizeX(convert(sizeX, EndiannessStructureFields.PSG_PUB_KEY_SIZE_X));
        psgPublicKey.setSizeY(convert(sizeY, EndiannessStructureFields.PSG_PUB_KEY_SIZE_Y));
        psgPublicKey.setCurveMagic(convert(PsgCurveType.fromCurveSpec(curvePoint.getCurveSpec()).getMagic(),
            EndiannessStructureFields.PSG_PUB_KEY_CURVE_MAGIC));
        psgPublicKey.setPermissions(convert(publicKeyPermissions, EndiannessStructureFields.PSG_PUB_KEY_PERMISSIONS));
        psgPublicKey.setCancellation(
            convert(publicKeyCancellation, EndiannessStructureFields.PSG_PUB_KEY_CANCELLATION));
        psgPublicKey.setPointX(curvePoint.getPointA());
        psgPublicKey.setPointY(curvePoint.getPointB());
        return psgPublicKey;
    }

    public PsgPublicKeyBuilder parse(String data) throws PsgPubKeyException {
        return parse(fromHex(data));
    }

    public PsgPublicKeyBuilder parse(byte[] data) throws PsgPubKeyException {
        return parse(ByteBufferSafe.wrap(data));
    }

    public PsgPublicKeyBuilder parse(ByteBufferSafe buffer) throws PsgPubKeyException {
        magic = PsgPublicKeyMagic.from(convertInt(buffer.getInt(), EndiannessStructureFields.PSG_PUB_KEY_MAGIC));
        sizeX = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_PUB_KEY_SIZE_X);
        sizeY = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_PUB_KEY_SIZE_Y);
        final PsgCurveType curveType = PsgCurveType.fromMagic(convertInt(buffer.getInt(),
            EndiannessStructureFields.PSG_PUB_KEY_CURVE_MAGIC));
        publicKeyPermissions = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_PUB_KEY_PERMISSIONS);
        publicKeyCancellation = convertInt(buffer.getInt(), EndiannessStructureFields.PSG_PUB_KEY_CANCELLATION);
        this.curvePoint = CurvePoint.from(buffer, curveType.getCurveSpec());
        return this;
    }
}
