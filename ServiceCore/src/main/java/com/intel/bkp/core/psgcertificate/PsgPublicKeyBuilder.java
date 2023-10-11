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

import com.intel.bkp.core.decoding.EncoderDecoder;
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.endianness.StructureType;
import com.intel.bkp.core.exceptions.ParseStructureException;
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

import static com.intel.bkp.core.endianness.StructureField.PSG_PUB_KEY_CANCELLATION;
import static com.intel.bkp.core.endianness.StructureField.PSG_PUB_KEY_CURVE_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_PUB_KEY_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_PUB_KEY_PERMISSIONS;
import static com.intel.bkp.core.endianness.StructureField.PSG_PUB_KEY_SIZE_X;
import static com.intel.bkp.core.endianness.StructureField.PSG_PUB_KEY_SIZE_Y;

@Getter
public class PsgPublicKeyBuilder extends StructureBuilder<PsgPublicKeyBuilder, PsgPublicKey> {

    private PsgPublicKeyMagic magic = PsgPublicKeyMagic.M1_MAGIC;
    public static final int PSG_SHA384_FORMAT_LEN = 120;
    private static final int PUBKEY_METADATA_SIZE = 6 * Integer.BYTES;
    private int publicKeyPermissions = ModifyBitsBuilder.fromNone().build();
    private int publicKeyCancellation = ModifyBitsBuilder.fromAll().build();
    private int sizeX = 0;
    private int sizeY = 0;
    private CurvePoint curvePoint;
    private boolean empty;

    public PsgPublicKeyBuilder() {
        super(StructureType.PSG_PUBLIC_KEY);
        withEncoderDecoder(EncoderDecoder.HEX);
    }

    @Override
    public PsgPublicKeyBuilder self() {
        return this;
    }

    public int totalLen() {
        return (2 * curvePoint.getCurveSpec().getSize()) + PUBKEY_METADATA_SIZE;
    }

    public PsgPublicKeyBuilder magic(PsgPublicKeyMagic magic) {
        this.magic = magic;
        return this;
    }

    public PsgPublicKeyBuilder empty() {
        this.empty = true;
        magic(PsgPublicKeyMagic.EMPTY);
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

    @Override
    public PsgPublicKey build() {
        final var psgPublicKey = new PsgPublicKey();

        if (PsgPublicKeyMagic.EMPTY == magic) {
            return buildEmpty(psgPublicKey);
        }

        psgPublicKey.setMagic(convert(magic.getValue(), PSG_PUB_KEY_MAGIC));
        psgPublicKey.setSizeX(convert(sizeX, PSG_PUB_KEY_SIZE_X));
        psgPublicKey.setSizeY(convert(sizeY, PSG_PUB_KEY_SIZE_Y));
        psgPublicKey.setCurveMagic(convert(PsgCurveType.fromCurveSpec(curvePoint.getCurveSpec()).getMagic(),
            PSG_PUB_KEY_CURVE_MAGIC));
        psgPublicKey.setPermissions(convert(publicKeyPermissions, PSG_PUB_KEY_PERMISSIONS));
        psgPublicKey.setCancellation(convert(publicKeyCancellation, PSG_PUB_KEY_CANCELLATION));
        psgPublicKey.setPointX(curvePoint.getPointA());
        psgPublicKey.setPointY(curvePoint.getPointB());
        return psgPublicKey;
    }

    private PsgPublicKey buildEmpty(PsgPublicKey psgPublicKey) {
        final byte[] emptyInteger = new byte[Integer.BYTES];
        psgPublicKey.setMagic(emptyInteger);
        psgPublicKey.setSizeX(emptyInteger);
        psgPublicKey.setSizeY(emptyInteger);
        psgPublicKey.setCurveMagic(emptyInteger);
        psgPublicKey.setPermissions(emptyInteger);
        psgPublicKey.setCancellation(emptyInteger);
        int emptySize = (PSG_SHA384_FORMAT_LEN - PUBKEY_METADATA_SIZE) / 2;
        psgPublicKey.setPointX(new byte[emptySize]);
        psgPublicKey.setPointY(new byte[emptySize]);
        return psgPublicKey;
    }

    public PsgPublicKeyBuilder parse(ByteBufferSafe buffer) throws ParseStructureException {
        magic = PsgPublicKeyMagic.from(convertInt(buffer.getInt(), PSG_PUB_KEY_MAGIC));
        if (PsgPublicKeyMagic.EMPTY == magic) {
            buffer.skip(PSG_SHA384_FORMAT_LEN - Integer.BYTES);
            return this;
        }
        sizeX = convertInt(buffer.getInt(), PSG_PUB_KEY_SIZE_X);
        sizeY = convertInt(buffer.getInt(), PSG_PUB_KEY_SIZE_Y);
        final PsgCurveType curveType = PsgCurveType.fromMagic(convertInt(buffer.getInt(),
            PSG_PUB_KEY_CURVE_MAGIC));
        publicKeyPermissions = convertInt(buffer.getInt(), PSG_PUB_KEY_PERMISSIONS);
        publicKeyCancellation = convertInt(buffer.getInt(), PSG_PUB_KEY_CANCELLATION);
        curvePoint = CurvePoint.from(buffer, curveType.getCurveSpec());
        return this;
    }
}
