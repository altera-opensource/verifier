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
import com.intel.bkp.core.endianess.maps.PsgPublicKeyEndianessMapImpl;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgPublicKeyBuilderException;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKey;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.utils.ModifyBitsBuilder;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.PaddingUtils;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

import static com.intel.bkp.utils.HexConverter.fromHex;

@Getter
@NoArgsConstructor
public class PsgPublicKeyBuilder extends PsgDataBuilder<PsgPublicKeyBuilder> {

    private PsgPublicKeyMagic magic = PsgPublicKeyMagic.M1_MAGIC;
    private PsgCurveType curveType = PsgCurveType.SECP384R1;
    private int publicKeyPermissions = ModifyBitsBuilder.fromNone().build();
    private int publicKeyCancellation = ModifyBitsBuilder.fromAll().build();
    private int sizeX = 0;
    private int sizeY = 0;
    private byte[] pointX = new byte[curveType.getSize()];
    private byte[] pointY = new byte[curveType.getSize()];

    @Override
    public EndianessStructureType currentStructureMap() {
        return EndianessStructureType.PSG_PUBLIC_KEY;
    }

    @Override
    public PsgPublicKeyBuilder withActor(EndianessActor actor) {
        changeActor(actor);
        return this;
    }

    @Override
    protected void initStructureMap(EndianessStructureType currentStructureType, EndianessActor currentActor) {
        maps.put(currentStructureType, new PsgPublicKeyEndianessMapImpl(currentActor));
    }

    public int totalLen() {
        return PsgPublicKeyHelper.getTotalPublicKeySize(curveType);
    }

    public PsgPublicKeyBuilder magic(PsgPublicKeyMagic magic) {
        this.magic = magic;
        return this;
    }

    public PsgPublicKeyBuilder curveType(PsgCurveType curveType) {
        this.curveType = curveType;
        initializeXY();
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

    public PsgPublicKeyBuilder publicKey(byte[] encodedPublicKey) throws PsgPublicKeyBuilderException {
        try {
            ECPublicKey publicKey =
                (ECPublicKey) CryptoUtils.toPublicEncodedBC(encodedPublicKey, SecurityKeyType.EC.name());
            preparePublicKey(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new PsgPublicKeyBuilderException();
        }
        return this;
    }

    public PsgPublicKeyBuilder publicKey(ECPublicKey publicKey) {
        preparePublicKey(publicKey);
        return this;
    }

    public PsgPublicKeyBuilder publicKeyPointXY(byte[] publicKeyXY) {
        parsePointXY(publicKeyXY);
        return this;
    }

    public PsgPublicKey build() {
        PsgPublicKey psgPublicKey = new PsgPublicKey();
        psgPublicKey.setMagic(convert(magic.getValue(), EndianessStructureFields.PSG_PUB_KEY_MAGIC));
        psgPublicKey.setSizeX(convert(sizeX, EndianessStructureFields.PSG_PUB_KEY_SIZE_X));
        psgPublicKey.setSizeY(convert(sizeY, EndianessStructureFields.PSG_PUB_KEY_SIZE_Y));
        psgPublicKey.setCurveMagic(convert(curveType.getMagic(), EndianessStructureFields.PSG_PUB_KEY_CURVE_MAGIC));
        psgPublicKey.setPermissions(convert(publicKeyPermissions, EndianessStructureFields.PSG_PUB_KEY_PERMISSIONS));
        psgPublicKey.setCancellation(convert(publicKeyCancellation, EndianessStructureFields.PSG_PUB_KEY_CANCELLATION));
        psgPublicKey.setPointX(convert(pointX, EndianessStructureFields.PSG_PUB_KEY_POINT_X));
        psgPublicKey.setPointY(convert(pointY, EndianessStructureFields.PSG_PUB_KEY_POINT_Y));
        return psgPublicKey;
    }

    public PsgPublicKeyBuilder parse(String data) throws PsgCertificateException {
        return parse(fromHex(data));
    }

    public PsgPublicKeyBuilder parse(byte[] data) throws PsgCertificateException {
        return parse(ByteBufferSafe.wrap(data));
    }

    public PsgPublicKeyBuilder parse(ByteBufferSafe buffer) throws PsgCertificateException {
        magic = PsgPublicKeyHelper.parsePublicKeyMagic(convertInt(buffer.getInt(),
            EndianessStructureFields.PSG_PUB_KEY_MAGIC));
        sizeX = convertInt(buffer.getInt(), EndianessStructureFields.PSG_PUB_KEY_SIZE_X);
        sizeY = convertInt(buffer.getInt(), EndianessStructureFields.PSG_PUB_KEY_SIZE_Y);
        curveType = PsgPublicKeyHelper.parseCurveType(convertInt(buffer.getInt(),
            EndianessStructureFields.PSG_PUB_KEY_CURVE_MAGIC));
        publicKeyPermissions = convertInt(buffer.getInt(), EndianessStructureFields.PSG_PUB_KEY_PERMISSIONS);
        publicKeyCancellation = convertInt(buffer.getInt(), EndianessStructureFields.PSG_PUB_KEY_CANCELLATION);

        pointX = convert(getPointArrayFrom(buffer), EndianessStructureFields.PSG_PUB_KEY_POINT_X);
        pointY = convert(getPointArrayFrom(buffer), EndianessStructureFields.PSG_PUB_KEY_POINT_Y);

        return this;
    }

    public void verify() throws PsgCertificateException {
        PsgPublicKeyHelper.verifyPoint(this);
    }

    private static byte[] removePadding(PsgCurveType curveType, byte[] arr) {
        return PaddingUtils.alignTo(arr, curveType.getSize());
    }

    private void initializeXY() {
        pointX = new byte[curveType.getSize()];
        pointY = new byte[curveType.getSize()];
    }

    private void preparePublicKey(ECPublicKey pubKey) {
        byte[] coordX = pubKey.getW().getAffineX().toByteArray();
        byte[] coordY = pubKey.getW().getAffineY().toByteArray();
        parsePointXY(coordX, coordY);
    }

    private void parsePointXY(byte[] pointX, byte[] pointY) {
        ByteBufferSafe.wrap(removePadding(curveType, pointX)).getAll(this.pointX);
        ByteBufferSafe.wrap(removePadding(curveType, pointY)).getAll(this.pointY);
    }

    private void parsePointXY(byte[] pointXY) {
        ByteBufferSafe.wrap(pointXY).get(this.pointX).getAll(this.pointY);
    }

    private byte[] getPointArrayFrom(ByteBufferSafe buffer) {
        byte[] array = buffer.arrayFromInt(curveType.getSize());
        buffer.get(array);
        return array;
    }
}
