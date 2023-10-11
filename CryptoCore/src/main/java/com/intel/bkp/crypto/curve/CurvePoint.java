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

package com.intel.bkp.crypto.curve;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.interfaces.ICurveSpec;
import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.PaddingUtils;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;

import static com.intel.bkp.crypto.asn1.Asn1ParsingUtils.extractR;
import static com.intel.bkp.crypto.asn1.Asn1ParsingUtils.extractS;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_KEY;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class CurvePoint implements ICurveSpec {

    private final byte[] pointA;
    private final byte[] pointB;
    private final CurveSpec curveSpec;

    public static CurvePoint from(byte[] pointX, byte[] pointY, CurveSpec curveSpec) {
        final int size = curveSpec.getSize();
        return new CurvePoint(
            PaddingUtils.alignLeft(pointX, size),
            PaddingUtils.alignLeft(pointY, size),
            curveSpec
        );
    }

    public static CurvePoint from(PublicKey publicKey, CurveSpec curveSpec) {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Provided public key is not EC public key");
        }

        final ECPoint ecPoint = ((ECPublicKey) publicKey).getW();
        final byte[] coordX = ecPoint.getAffineX().toByteArray();
        final byte[] coordY = ecPoint.getAffineY().toByteArray();
        return from(coordX, coordY, curveSpec);
    }

    public static CurvePoint from(PublicKey publicKey) {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Provided public key is not EC public key");
        }
        return from(publicKey, CurveSpec.getCurveSpec(publicKey));
    }

    public static CurvePoint from(String pointX, String pointY, CurveSpec pointSpec) {
        return from(fromHex(pointX), fromHex(pointY), pointSpec);
    }

    public static CurvePoint from(ByteBufferSafe buffer, CurveSpec pointSpec) {
        final byte[] pointX = getPointArrayFrom(buffer, pointSpec);
        final byte[] pointY = getPointArrayFrom(buffer, pointSpec);
        return from(pointX, pointY, pointSpec);
    }

    public static CurvePoint fromPubKey(byte[] pointXY, CurveSpec curveSpec) {
        final int size = curveSpec.getSize();
        final byte[] pointX = new byte[size];
        final byte[] pointY = new byte[size];
        ByteBufferSafe.wrap(pointXY).get(pointX).getAll(pointY);
        return from(pointX, pointY, curveSpec);
    }

    public static CurvePoint fromPubKeyPem(byte[] pubKeyPemFile)
        throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final byte[] encodedPubKey = PemFormatEncoder.decode(pubKeyPemFile);
        return fromPubKeyEncoded(encodedPubKey);
    }

    public static CurvePoint fromPubKeyEncoded(byte[] encodedPublicKey)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        return from(CryptoUtils.toPublicEncodedBC(encodedPublicKey, EC_KEY));
    }

    public static CurvePoint fromPubKeyEncoded(byte[] encodedPublicKey, CurveSpec pointSpec)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        return from(CryptoUtils.toPublicEncodedBC(encodedPublicKey, EC_KEY), pointSpec);
    }

    public static CurvePoint fromSignature(byte[] signature, ICurveSpec spec) {
        return from(extractR(signature), extractS(signature), spec.getCurveSpec());
    }

    public String generateFingerprint() {
        return CryptoUtils.generateFingerprint(getAlignedDataToSize());
    }

    public String generateSha256Fingerprint() {
        return CryptoUtils.generateSha256Fingerprint(getAlignedDataToSize());
    }

    public byte[] getAlignedDataToSize() {
        return ByteBuffer.allocate(getCurveSpec().getSize() * 2)
            .put(getPointA())
            .put(getPointB())
            .array();
    }

    public String getHexPointA() {
        return toHex(pointA);
    }

    public String getHexPointB() {
        return toHex(pointB);
    }

    @Override
    public String toString() {
        return CurvePoint.class.getSimpleName() + "{"
            + "pointA=" + getHexPointA()
            + ", pointB=" + getHexPointB()
            + ", curveSpec=" + curveSpec
            + '}';
    }

    private static byte[] getPointArrayFrom(ByteBufferSafe buffer, CurveSpec curveSpec) {
        final byte[] array = buffer.arrayFromInt(curveSpec.getSize());
        buffer.get(array);
        return array;
    }
}
