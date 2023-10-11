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

package com.intel.bkp.crypto;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.impl.AesUtils;
import com.intel.bkp.crypto.impl.CertificateUtils;
import com.intel.bkp.crypto.impl.EcUtils;
import com.intel.bkp.crypto.impl.HashUtils;
import com.intel.bkp.crypto.impl.PublicKeyUtils;
import com.intel.bkp.crypto.impl.RsaUtils;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public abstract class CryptoUtils {

    @Getter
    protected static Provider bouncyCastleProvider = new BouncyCastleProvider();

    public static KeyPair genEcdhBC() throws KeystoreGenericException {
        return EcUtils.genEc(bouncyCastleProvider, CryptoConstants.ECDH_KEY, CryptoConstants.EC_CURVE_SPEC_384);
    }

    public static byte[] genEcdhSharedSecretBC(PrivateKey privateKey, PublicKey publicKey)
        throws KeystoreGenericException {
        return EcUtils.genEcdhSharedSecret(bouncyCastleProvider, privateKey, publicKey,
            CryptoConstants.KEY_AGREEMENT_ALG_TYPE);
    }

    public static KeyPair genEcdsaBC() throws KeystoreGenericException {
        return genEcdsaBC(CryptoConstants.EC_CURVE_SPEC_384);
    }

    public static KeyPair genEcdsaBC(String curveSpec) throws KeystoreGenericException {
        return EcUtils.genEc(bouncyCastleProvider, CryptoConstants.EC_KEY, curveSpec);
    }

    public static ECPublicKeySpec getEcKeySpec(BigInteger affineX, BigInteger affineY, String curveType) {
        return EcUtils.getEcKeySpec(affineX, affineY, curveType);
    }

    public static ECPrivateKeySpec getEcKeySpec(BigInteger privKey, String curveType) {
        return EcUtils.getEcKeySpec(privKey, curveType);
    }

    public static org.bouncycastle.math.ec.ECPoint getCurveGenerator(String curveType) {
        return EcUtils.getCurveGenerator(curveType);
    }

    public static byte[] signEcDataBC(PrivateKey privateKey, byte[] data)
        throws KeystoreGenericException {
        return EcUtils.signEcData(privateKey, data, CryptoConstants.SHA384_WITH_ECDSA, bouncyCastleProvider);
    }

    // :TODO - curve spec should be an enum with size
    public static PrivateKey toEcPrivateBC(byte[] privateKeyBytes, String algorithm)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        return EcUtils.toPrivate(privateKeyBytes, algorithm, CryptoConstants.EC_CURVE_SPEC_384, bouncyCastleProvider);
    }

    public static PublicKey toEcPublicBC(byte[] publicKeyBytes, String algorithm, String curveType)
        throws NoSuchAlgorithmException, InvalidKeySpecException, EcdhKeyPairException {
        return EcUtils.toPublic(publicKeyBytes, algorithm, curveType, bouncyCastleProvider);
    }

    public static byte[] getBytesFromPubKey(ECPublicKey publicKey, int pubKeyLen) {
        return EcUtils.getRawXYBytesFromPubKey(publicKey, pubKeyLen);
    }

    public static int getPubKeyXYLenForPubKey(ECPublicKey publicKey) {
        return EcUtils.getPubKeyXYLenForPubKey(publicKey);
    }

    public static byte[] getBytesFromPrivKey(ECPrivateKey privateKey) {
        return EcUtils.getBytesFromPrivKey(privateKey);
    }

    public static SecretKey genAesBC() throws KeystoreGenericException {
        return AesUtils.genAES(bouncyCastleProvider, CryptoConstants.AES_KEY, CryptoConstants.AES_KEY_SIZE);
    }

    public static SecretKey genAesKeyFromByteArray(byte[] keyBytes) {
        return AesUtils.genAesKeyFromByteArray(keyBytes, CryptoConstants.AES_KEY);
    }

    public static KeyPair genRsaBC() throws KeystoreGenericException {
        return RsaUtils.genRSA(CryptoConstants.RSA_KEY, CryptoConstants.RSA_KEY_SIZE, bouncyCastleProvider);
    }

    public static PublicKey restoreRSAPubKeyBC(byte[] rsaKey) throws KeystoreGenericException {
        return RsaUtils.restoreRSAPubKey(rsaKey, CryptoConstants.RSA_KEY, bouncyCastleProvider);
    }

    public static PublicKey toPublicEncodedBC(byte[] publicKeyBytes, String algorithm) throws NoSuchAlgorithmException,
        InvalidKeySpecException {
        return PublicKeyUtils.toPublicEncoded(publicKeyBytes, algorithm, bouncyCastleProvider);
    }

    public static X500Name getIssuer(String commonName, String organizationalUnit) {
        return CertificateUtils.getIssuer(commonName, organizationalUnit);
    }

    public static String generateFingerprint(byte[] data) {
        return HashUtils.generateFingerprint(data);
    }

    public static String generateFingerprint(String data) {
        return HashUtils.generateFingerprint(data);
    }

    public static String generateSha256Fingerprint(byte[] data) {
        return HashUtils.generateSha256Fingerprint(data);
    }

    public static int getIntForSha384(byte[] data) {
        return HashUtils.getIntForSha384(data);
    }

    public static int getIntForSha256(byte[] data) {
        return HashUtils.getIntForSha256(data);
    }

    public static byte[] get20MSBytesForSha384(byte[] data) {
        return HashUtils.getMSBytesForSha384(data, 20);
    }
}
