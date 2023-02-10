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

package com.intel.bkp.crypto.impl;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.crypto.ecdh.EcdhVerifier;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.crypto.exceptions.InvalidSignatureException;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.PaddingUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import static com.intel.bkp.crypto.CryptoUtils.getBytesFromPubKey;
import static com.intel.bkp.crypto.CryptoUtils.toPublicEncodedBC;
import static com.intel.bkp.crypto.asn1.Asn1ParsingUtils.convertToDerSignature;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class EcUtils {

    public static KeyPair genEc(Provider provider, String algorithm, String ecCurve384spec)
        throws KeystoreGenericException {

        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(ecCurve384spec);
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
            keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new KeystoreGenericException("Failed to create EC key in secure enclave.", e);
        }
    }

    public static byte[] genEcdhSharedSecret(Provider provider, PrivateKey privateKey, PublicKey publicKey,
                                             String keyAgreementAlgName)
        throws KeystoreGenericException {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(keyAgreementAlgName, provider);
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new KeystoreGenericException("Failed to establish ECDH secure connection.", e);
        }
    }

    public static ECPublicKeySpec getEcKeySpec(BigInteger affineX, BigInteger affineY, String curveType) {
        return new ECPublicKeySpec(new ECPoint(affineX, affineY), getEcParameterSpec(curveType));
    }

    public static ECPrivateKeySpec getEcKeySpec(BigInteger privKey, String curveType) {
        return new ECPrivateKeySpec(privKey, getEcParameterSpec(curveType));
    }

    public static org.bouncycastle.math.ec.ECPoint getCurveGenerator(String curveType) {
        return ECNamedCurveTable.getParameterSpec(curveType).getG();
    }

    public static byte[] signEcData(PrivateKey privateKey, byte[] data, String sigAlgorithmName, Provider provider)
        throws KeystoreGenericException {
        try {
            Signature ecdsaSign = Signature.getInstance(sigAlgorithmName, provider);
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(data);
            return ecdsaSign.sign();
        } catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new KeystoreGenericException("Failed to sign data", e);
        }
    }

    public static boolean sigVerify(X509Certificate certificate, byte[] data, byte[] signature, String sigAlgorithmName,
                                    Provider provider) throws InvalidSignatureException {
        try {
            Signature ecdsaSign = Signature.getInstance(sigAlgorithmName, provider);
            ecdsaSign.initVerify(certificate);
            ecdsaSign.update(data);
            return ecdsaSign.verify(signature);
        } catch (Exception e) {
            throw new InvalidSignatureException("Failed to check signature", e);
        }
    }

    public static boolean sigVerify(PublicKey publicKey, byte[] data, byte[] signature, String sigAlgorithmName,
                                    Provider provider)
        throws InvalidSignatureException {
        try {
            Signature ecdsaSign = Signature.getInstance(sigAlgorithmName, provider);
            ecdsaSign.initVerify(publicKey);
            ecdsaSign.update(data);
            return ecdsaSign.verify(signature);
        } catch (Exception e) {
            throw new InvalidSignatureException("Failed to check signature", e);
        }
    }

    public static boolean sigVerify(PublicKey publicKey, byte[] data, byte[] signature, String sigAlgorithmName)
        throws InvalidSignatureException {
        return sigVerify(publicKey, data, signature, sigAlgorithmName, CryptoUtils.getBouncyCastleProvider());
    }

    public static boolean sigVerify(PublicKey publicKey, byte[] data, CurvePoint signaturePoint,
                                    String sigAlgorithmName)
        throws InvalidSignatureException {
        final byte[] signature;
        try {
            signature = convertToDerSignature(signaturePoint.getPointA(), signaturePoint.getPointB());
        } catch (IOException e) {
            throw new InvalidSignatureException("Failed to convert point to DER format", e);
        }
        return sigVerify(publicKey, data, signature, sigAlgorithmName, CryptoUtils.getBouncyCastleProvider());
    }

    public static PrivateKey toPrivate(byte[] privateKeyBytes, String algorithm, String ecCurve384spec,
                                       Provider bouncyCastleProvider)
        throws NoSuchAlgorithmException, InvalidKeySpecException {

        ECPrivateKeySpec keySpec = getEcKeySpec(new BigInteger(privateKeyBytes), ecCurve384spec);
        KeyFactory kf = KeyFactory.getInstance(algorithm, bouncyCastleProvider);
        return kf.generatePrivate(keySpec);
    }

    public static PublicKey toPublic(byte[] publicKeyBytes, String algorithm, String curveType,
                                     Provider bouncyCastleProvider)
        throws NoSuchAlgorithmException, InvalidKeySpecException, EcdhKeyPairException {

        int pubKeyXYLen = getPubKeyXYLenFromCurveType(curveType);

        final ByteBufferSafe bufferSafe = ByteBufferSafe.wrap(publicKeyBytes);
        final byte[] xBytes = bufferSafe.arrayFromInt(pubKeyXYLen);
        final byte[] yBytes = bufferSafe.arrayFromInt(pubKeyXYLen);

        bufferSafe.get(xBytes);
        bufferSafe.get(yBytes);

        final byte[] xBytesPadded = PaddingUtils.padLeft(xBytes, pubKeyXYLen + 1);
        final byte[] yBytesPadded = PaddingUtils.padLeft(yBytes, pubKeyXYLen + 1);

        BigInteger affineX = new BigInteger(xBytesPadded);
        BigInteger affineY = new BigInteger(yBytesPadded);

        if (!EcdhVerifier.isValid(affineX, affineY, curveType)) {
            throw new EcdhKeyPairException("PublicKey is not valid");
        }

        ECPublicKeySpec keySpec = getEcKeySpec(affineX, affineY, curveType);

        KeyFactory kf = KeyFactory.getInstance(algorithm, bouncyCastleProvider);
        return kf.generatePublic(keySpec);
    }

    public static byte[] getRawXYBytesFromPubKey(ECPublicKey publicKey, int dhPubKeyLen) {
        final ECPoint pubKey = publicKey.getW();

        final byte[] pubX = pubKey.getAffineX().toByteArray();
        final byte[] pubY = pubKey.getAffineY().toByteArray();

        return ByteBuffer.allocate(dhPubKeyLen)
            .put(PaddingUtils.alignLeft(pubX, dhPubKeyLen / 2))
            .put(PaddingUtils.alignLeft(pubY, dhPubKeyLen / 2))
            .array();
    }

    public static byte[] getBytesFromPrivKey(ECPrivateKey privateKey) {
        return privateKey.getS().toByteArray();
    }

    public static int getPubKeyXYLenForPubKey(ECPublicKey publicKey) {
        return 2 * getPubKeyXYLenFromCurveType(((ECNamedCurveSpec) publicKey.getParams()).getName());
    }

    public static String generateFingerprint(PublicKey publicKey)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        final ECPublicKey ecPubKey = (ECPublicKey) toPublicEncodedBC(publicKey.getEncoded(), SecurityKeyType.EC.name());
        final byte[] bytesFromPubKey = getBytesFromPubKey(ecPubKey, getPubKeyXYLenForPubKey(ecPubKey));
        return HashUtils.generateFingerprint(bytesFromPubKey);
    }

    private static ECParameterSpec getEcParameterSpec(String curveType) {
        ECNamedCurveParameterSpec curveParameterSpec = ECNamedCurveTable.getParameterSpec(curveType);
        EllipticCurve ellipticCurve = EC5Util.convertCurve(curveParameterSpec.getCurve(), curveParameterSpec.getSeed());
        return EC5Util.convertSpec(ellipticCurve, curveParameterSpec);
    }

    private static int getPubKeyXYLenFromCurveType(String curveType) {
        if (Objects.equals(curveType, CryptoConstants.EC_CURVE_SPEC_384)) {
            return CryptoConstants.SHA384_LEN;
        } else {
            return CryptoConstants.SHA256_LEN;
        }
    }
}
