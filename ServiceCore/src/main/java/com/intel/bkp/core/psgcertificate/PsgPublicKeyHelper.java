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

import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKey;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.PaddingUtils;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import static com.intel.bkp.crypto.CryptoUtils.getEcKeySpec;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class PsgPublicKeyHelper {

    private static final int PUBKEY_METADATA_SIZE = 6 * Integer.BYTES;

    public static String generateFingerprint(PsgPublicKey psgPublicKey) {
        byte[] pointX = psgPublicKey.getPointX();
        byte[] pointY = psgPublicKey.getPointY();
        return CryptoUtils.generateFingerprint(
            ByteBuffer.allocate(pointX.length + pointY.length).put(pointX).put(pointY).array());
    }

    public static String generateFingerprint(byte[] psgPublicKey) throws PsgCertificateException {
        final PsgPublicKey parsedPsgPublicKey = new PsgPublicKeyBuilder().parse(psgPublicKey).build();
        return generateFingerprint(parsedPsgPublicKey);
    }

    public static String generateFingerprint(PsgPublicKeyBuilder psgPublicKeyBuilder) {
        return generateFingerprint(psgPublicKeyBuilder.build());
    }

    public static String generateFingerprint(ECPublicKey pubKey) {
        final byte[] bytesFromPubKey = CryptoUtils.getBytesFromPubKey(pubKey,
            CryptoUtils.getPubKeyXYLenForPubKey(pubKey));
        return CryptoUtils.generateFingerprint(bytesFromPubKey);
    }

    public static boolean areEqual(ECPublicKey pubKey, PsgPublicKeyBuilder psgPublicKeyBuilder) {
        return generateFingerprint(pubKey).equals(generateFingerprint(psgPublicKeyBuilder));
    }

    public static PsgPublicKeyMagic parsePublicKeyMagic(int magic) throws PsgCertificateException {
        if (PsgPublicKeyMagic.MANIFEST_MAGIC.getValue() == magic) {
            return PsgPublicKeyMagic.MANIFEST_MAGIC;
        } else if (PsgPublicKeyMagic.M1_MAGIC.getValue() == magic) {
            return PsgPublicKeyMagic.M1_MAGIC;
        } else {
            throw new PsgCertificateException("Invalid public key magic");
        }
    }

    public static PsgCurveType parseCurveType(PsgPublicKey psgPublicKey) throws PsgCertificateException {
        return parseCurveType(ByteBufferSafe.wrap(psgPublicKey.getCurveMagic()).getInt());
    }

    public static PsgCurveType parseCurveType(byte[] curveTypeMagic) throws PsgCertificateException {
        return parseCurveType(ByteBufferSafe.wrap(curveTypeMagic).getInt());
    }

    public static PsgCurveType parseCurveType(int curveTypeMagic) throws PsgCertificateException {
        if (PsgCurveType.SECP384R1.getMagic() == curveTypeMagic) {
            return PsgCurveType.SECP384R1;
        } else if (PsgCurveType.SECP256R1.getMagic() == curveTypeMagic) {
            return PsgCurveType.SECP256R1;
        } else {
            throw new PsgCertificateException("Invalid curve type magic provided");
        }
    }

    public static void verifyPoint(PsgPublicKeyBuilder psgPublicKeyBuilder) throws PsgCertificateException {
        PsgCurveType curveType = parseCurveType(psgPublicKeyBuilder.getCurveType().getMagic());
        Point pointXY = getPointFrom(psgPublicKeyBuilder);

        if (!isValid(curveType, pointXY)) {
            throw new PsgCertificateException("PublicKey is not valid - wrong curve point");
        }
    }

    public static int getTotalPublicKeySize(PsgCurveType curveType) {
        return (2 * curveType.getSize()) + PUBKEY_METADATA_SIZE;
    }

    private static boolean isValid(PsgCurveType curveType, Point pointXY) {
        switch (curveType) {
            case SECP256R1:
                return new SecP256R1Curve().createPoint(pointXY.affineX, pointXY.affineY).isValid();
            case SECP384R1:
            default:
                return new SecP384R1Curve().createPoint(pointXY.affineX, pointXY.affineY).isValid();
        }
    }

    public static PublicKey toPublic(byte[] psgPublicKey) throws PsgCertificateException, InvalidKeySpecException,
        NoSuchAlgorithmException {
        return toPublic(new PsgPublicKeyBuilder().parse(psgPublicKey));
    }

    public static PublicKey toPublic(PsgPublicKeyBuilder psgPublicKeyBuilder)
        throws NoSuchAlgorithmException, InvalidKeySpecException, PsgCertificateException {

        Point pointXY = getPointFrom(psgPublicKeyBuilder);

        ECPublicKeySpec keySpec =
            getEcKeySpec(pointXY.affineX, pointXY.affineY, getEcCurveTypeFrom(psgPublicKeyBuilder));
        KeyFactory kf = KeyFactory.getInstance(CryptoConstants.ECDSA_ALG_TYPE, CryptoUtils.getBouncyCastleProvider());
        return kf.generatePublic(keySpec);
    }

    private static Point getPointFrom(PsgPublicKeyBuilder pubKey) throws PsgCertificateException {
        PsgCurveType curveType = parseCurveType(pubKey.getCurveType().getMagic());
        final byte[] xBytesPadded = PaddingUtils.addPadding(pubKey.getPointX(), curveType.getSize() + 1);
        final byte[] yBytesPadded = PaddingUtils.addPadding(pubKey.getPointY(), curveType.getSize() + 1);

        BigInteger affineX = new BigInteger(xBytesPadded);
        BigInteger affineY = new BigInteger(yBytesPadded);

        return new Point(affineX, affineY);
    }

    private static String getEcCurveTypeFrom(PsgPublicKeyBuilder psgPublicKeyBuilder) throws PsgCertificateException {
        PsgCurveType curveType = parseCurveType(psgPublicKeyBuilder.getCurveType().getMagic());
        return PsgCurveType.SECP384R1 == curveType ? CryptoConstants.EC_CURVE_SPEC_384
                                                   : CryptoConstants.EC_CURVE_SPEC_256;
    }

    @AllArgsConstructor
    private static class Point {

        private final BigInteger affineX;
        private final BigInteger affineY;
    }
}
