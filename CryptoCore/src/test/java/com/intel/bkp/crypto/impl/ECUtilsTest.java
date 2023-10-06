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

package com.intel.bkp.crypto.impl;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.crypto.exceptions.InvalidSignatureException;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.provider.TestProvider;
import com.intel.bkp.test.KeyLoadUtils;
import com.intel.bkp.test.SigningUtils;
import com.intel.bkp.utils.PaddingUtils;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.pemToX509Certificate;
import static com.intel.bkp.test.AssertionUtils.assertThatArrayIsSubarrayOfAnotherArray;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ECUtilsTest {

    private static final String providerName = "test-provider";
    /**
     * Private key in PKCS8 format, generated using OpenSSL:
     * openssl ecparam -out ec_key_priv_384.pem -name secp384r1 -genkey
     * openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ec_key_priv_384.pem -out ec_key_priv_384_pkcs8.pem
     */
    private static final String privateKeyInPem = "-----BEGIN PRIVATE KEY-----\n"
        + "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBA7JKka6qMj2knBj2z\n"
        + "jljOP+RJppidjRf1UsvEBBsyOFukDyXRf+hVmasFQd0VAq2hZANiAAS8Ny9Iihrj\n"
        + "B8ye5ULeA8Z++I4iPWpSeAorokfdz8eDYEA9oXWSHzANi8t/BsxItcaGtV4vzApH\n"
        + "6+oYLL1uWqykDAdM1VNVQSvZly5v0iyPyYxQva5/BsrB/vl6rdw7ZvE=\n"
        + "-----END PRIVATE KEY-----";
    /**
     * Public key matching private key from privateKeyInPem, generated using OpenSSL:
     * openssl ec -in ec_key_priv_384.pem -pubout -out ec_key_pub_384.pem
     */
    private static final String publicKeyInPem = "-----BEGIN PUBLIC KEY-----\n"
        + "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEvDcvSIoa4wfMnuVC3gPGfviOIj1qUngK\n"
        + "K6JH3c/Hg2BAPaF1kh8wDYvLfwbMSLXGhrVeL8wKR+vqGCy9blqspAwHTNVTVUEr\n"
        + "2Zcub9Isj8mMUL2ufwbKwf75eq3cO2bx\n"
        + "-----END PUBLIC KEY-----";
    /**
     * Data used to generate signature stored in matchingSignature, with private key from privateKeyInPem
     */
    private static final byte[] signaturePayload = "data to sign\n".getBytes();
    /**
     * Signature over data from signaturePayload, generated using OpenSSL:
     * echo "data to sign" > signaturePayload.txt
     * openssl dgst -SHA384 -sign ec_key_priv_384.pem signaturePayload.txt > signature
     * hexdump -C signature
     */
    private static final byte[] matchingSignature = fromHex("3066023100ccb819aad3f430b03bf1b84dc6a"
        + "43b14de1b981d6effc675ea9c193182b0d83380c1f55975c57aa72ba0b7fc629a297302310090c2517d4501b6eaf84d139aa126915e"
        + "c88333f7f5409a45d6c79ba93fc9da07aa487ad880cdfbea3ca10793247faff4");
    /**
     * Signature over some random data, generated using OpenSSL:
     * echo "some random data" > differentSignaturePayload.txt
     * openssl dgst -SHA384 -sign ec_key_priv_384.pem differentSignaturePayload.txt > differentSignature
     * hexdump -C differentSignature
     */
    private static final byte[] notMatchingSignature = fromHex("306402306ce3bd1b7b3884ea9661b55d93"
        + "e23833f07cd8e95bbf40c146f65d5afaf2daaa67d9b53e781180cc1535a5ccff7c1fea02302572beeb3eca2cbfa852824910a02269a"
        + "b89deb268b89e19bf6de52ec5c8642d2b4cf0e5d8c8a1547d3a5738ffb6b6da");
    /**
     * Self-signed certificate with public key from publicKeyInPem, generated using OpenSSL:
     * openssl req -new -key ec_key_priv_384.pem -x509 -nodes -days 365 -out cert_384.pem
     */
    private static final String certInPem = "-----BEGIN CERTIFICATE-----\n"
        + "MIICSDCCAc2gAwIBAgIJAJQiq0yeP3BUMAoGCCqGSM49BAMCMGAxCzAJBgNVBAYT\n"
        + "AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\n"
        + "aXRzIFB0eSBMdGQxGTAXBgNVBAMMEHRlc3QgY2VydGlmaWNhdGUwHhcNMjEwNDI4\n"
        + "MTEyMzA1WhcNMjIwNDI4MTEyMzA1WjBgMQswCQYDVQQGEwJBVTETMBEGA1UECAwK\n"
        + "U29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRkw\n"
        + "FwYDVQQDDBB0ZXN0IGNlcnRpZmljYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\n"
        + "vDcvSIoa4wfMnuVC3gPGfviOIj1qUngKK6JH3c/Hg2BAPaF1kh8wDYvLfwbMSLXG\n"
        + "hrVeL8wKR+vqGCy9blqspAwHTNVTVUEr2Zcub9Isj8mMUL2ufwbKwf75eq3cO2bx\n"
        + "o1MwUTAdBgNVHQ4EFgQUw8WLPv5lu81B1iuLZFvPeYvHA9wwHwYDVR0jBBgwFoAU\n"
        + "w8WLPv5lu81B1iuLZFvPeYvHA9wwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD\n"
        + "AgNpADBmAjEA6taRwnNM2VRazmMeVPfLW5xPIUXSlPl6W7eZhc6JHHNq6WiuS/jG\n"
        + "JDA0v5bYltJHAjEA2KPYU78s3dr7INjOcn2RTwEbDD08KLrLKRsVgJdDwu7X9Z1h\n"
        + "Ps6zmjaOi8qgbeDD\n"
        + "-----END CERTIFICATE-----";

    private Provider provider;

    @Test
    void genECDH_throwsBKPInternalServerExceptionDueToNoAlgorithm() {
        //given
        provider = new TestProvider(providerName, "1.0", "info");

        //when-then
        assertThrows(KeystoreGenericException.class, () -> EcUtils.genEc(provider,
            CryptoConstants.ECDH_KEY, CryptoConstants.EC_CURVE_SPEC_384));
    }

    @Test
    void genECDSA_throwsBKPInternalServerExceptionDueToNoAlgorithm() {
        //given
        provider = new TestProvider(providerName, "1.0", "info");

        //when-then
        assertThrows(KeystoreGenericException.class, () -> EcUtils.genEc(provider,
            CryptoConstants.EC_KEY, CryptoConstants.EC_CURVE_SPEC_384));
    }

    @Test
    public void genECDH() throws KeystoreGenericException {
        // when
        KeyPair result = EcUtils.genEc(CryptoUtils.getBouncyCastleProvider(), CryptoConstants.ECDH_KEY,
            CryptoConstants.EC_CURVE_SPEC_384);

        // then
        assertNotNull(result);
        assertEquals(CryptoConstants.ECDH_KEY, result.getPrivate().getAlgorithm());
    }

    @Test
    public void genECDSA() throws KeystoreGenericException {
        // when
        KeyPair result = EcUtils.genEc(CryptoUtils.getBouncyCastleProvider(), CryptoConstants.EC_KEY,
            CryptoConstants.EC_CURVE_SPEC_384);

        // then
        assertNotNull(result);
        assertEquals(CryptoConstants.EC_KEY, result.getPrivate().getAlgorithm());
    }

    @Test
    public void genEcdhSharedSecret() throws KeystoreGenericException {
        // given
        final KeyPair firstKeypair = CryptoUtils.genEcdhBC();
        final KeyPair secondKeypair = CryptoUtils.genEcdhBC();

        final PublicKey firstPublic = firstKeypair.getPublic();
        final PrivateKey firstPrivate = firstKeypair.getPrivate();

        final PublicKey secondPublic = secondKeypair.getPublic();
        final PrivateKey secondPrivate = secondKeypair.getPrivate();

        // when
        final byte[] bytesA = EcUtils.genEcdhSharedSecret(CryptoUtils.getBouncyCastleProvider(), firstPrivate,
            secondPublic, CryptoConstants.KEY_AGREEMENT_ALG_TYPE);
        final byte[] bytesB = EcUtils.genEcdhSharedSecret(CryptoUtils.getBouncyCastleProvider(), secondPrivate,
            firstPublic, CryptoConstants.KEY_AGREEMENT_ALG_TYPE);

        // then
        assertNotNull(bytesA);
        assertNotNull(bytesB);
        assertArrayEquals(bytesA, bytesB);
    }

    @Test
    public void genEcdhSharedSecret_IncorrectAlgorithm_Throws() throws KeystoreGenericException {
        // given
        final String incorrectAlgorithm = "ECDSA";

        final KeyPair firstKeypair = CryptoUtils.genEcdhBC();
        final KeyPair secondKeypair = CryptoUtils.genEcdhBC();

        final PrivateKey firstPrivate = firstKeypair.getPrivate();
        final PublicKey secondPublic = secondKeypair.getPublic();

        // when-then
        assertThrows(KeystoreGenericException.class, () ->
            EcUtils.genEcdhSharedSecret(CryptoUtils.getBouncyCastleProvider(), firstPrivate,
                secondPublic, incorrectAlgorithm));
    }

    @Test
    public void getEcKeySpec_WithPublicKey() throws KeystoreGenericException {
        // given
        KeyPair key = CryptoUtils.genEcdsaBC();
        ECPoint q = ((ECPublicKey) key.getPublic()).getW();
        BigInteger affineX = q.getAffineX();
        BigInteger affineY = q.getAffineY();

        // when
        ECPublicKeySpec result = EcUtils.getEcKeySpec(affineX, affineY, CryptoConstants.EC_CURVE_SPEC_384);

        // then
        assertNotNull(result);
        assertEquals(affineX, result.getW().getAffineX());
        assertEquals(affineY, result.getW().getAffineY());
    }

    @Test
    public void getEcKeySpec_WithPrivateKey() throws KeystoreGenericException {
        // given
        KeyPair key = CryptoUtils.genEcdsaBC();
        BigInteger d = ((ECPrivateKey) key.getPrivate()).getS();

        // when
        ECPrivateKeySpec result = EcUtils.getEcKeySpec(d, CryptoConstants.EC_CURVE_SPEC_384);

        // then
        assertNotNull(result);
        assertEquals(d, result.getS());
    }

    @Test
    public void getCurveGenerator() {
        // when
        org.bouncycastle.math.ec.ECPoint result = EcUtils.getCurveGenerator(CryptoConstants.EC_CURVE_SPEC_384);

        // then
        assertNotNull(result);
    }

    @Test
    public void signEcData() throws Exception {
        // given
        final byte[] testData = "data to sign\n".getBytes();
        final PrivateKey privateKey = KeyLoadUtils.getEcPrivateKeyFromPem(privateKeyInPem);
        final PublicKey publicKey = KeyLoadUtils.getEcPublicKeyFromPem(publicKeyInPem);

        // when
        final byte[] result = EcUtils.signEcData(privateKey, testData,
            CryptoConstants.SHA384_WITH_ECDSA, CryptoUtils.getBouncyCastleProvider());

        // then
        assertNotNull(result);
        assertTrue(EcUtils.sigVerify(publicKey, testData, result,
            CryptoConstants.SHA384_WITH_ECDSA, CryptoUtils.getBouncyCastleProvider()));
    }

    @Test
    public void signEcData_MismatchedAlgorithm_Throws() throws Exception {
        // given
        final String mismatchedAlgorithm = CryptoConstants.SHA384_WITH_RSA;
        final byte[] testData = "test".getBytes();
        final PrivateKey privateKey = KeyLoadUtils.getEcPrivateKeyFromPem(privateKeyInPem);

        // when-then
        assertThrows(KeystoreGenericException.class, () ->
            EcUtils.signEcData(privateKey, testData, mismatchedAlgorithm, CryptoUtils.getBouncyCastleProvider()));
    }

    @Test
    public void sigVerify_WithPublicKey() throws InvalidSignatureException, KeystoreGenericException {
        // given
        final String signingAlgorithm = CryptoConstants.SHA384_WITH_ECDSA;
        final String verifyingAlgorithm = signingAlgorithm;
        final byte[] testData = "Test".getBytes();
        final KeyPair key = CryptoUtils.genEcdsaBC();
        final byte[] signEcData = SigningUtils.signEcData(testData, key.getPrivate(), signingAlgorithm);
        // when
        final boolean result = EcUtils.sigVerify(key.getPublic(), testData, signEcData,
            verifyingAlgorithm, CryptoUtils.getBouncyCastleProvider());

        // then
        assertTrue(result);
    }

    @Test
    public void sigVerify_WithPublicKey_MismatchedAlgorithm_Throws() throws KeystoreGenericException {
        // given
        final String signingAlgorithm = CryptoConstants.SHA384_WITH_ECDSA;
        final String verifyingAlgorithm = CryptoConstants.SHA384_WITH_RSA;
        final byte[] testData = "Test".getBytes();
        final KeyPair key = CryptoUtils.genEcdsaBC();
        final byte[] signEcData = SigningUtils.signEcData(testData, key.getPrivate(), signingAlgorithm);
        // when-then
        assertThrows(InvalidSignatureException.class, () ->
            EcUtils.sigVerify(key.getPublic(), testData, signEcData,
                verifyingAlgorithm, CryptoUtils.getBouncyCastleProvider()));
    }

    @Test
    public void sigVerify_WithCertificate() throws Exception {
        // given
        final String matchingAlgorithm = CryptoConstants.SHA384_WITH_ECDSA;
        final X509Certificate cert = pemToX509Certificate(certInPem);

        // when
        final boolean matchingSignatureResult = EcUtils.sigVerify(cert, signaturePayload, matchingSignature,
            matchingAlgorithm, CryptoUtils.getBouncyCastleProvider());

        final boolean notMatchingSignatureResult = EcUtils.sigVerify(cert, signaturePayload, notMatchingSignature,
            matchingAlgorithm, CryptoUtils.getBouncyCastleProvider());

        // then
        assertTrue(matchingSignatureResult);
        assertFalse(notMatchingSignatureResult);
    }

    @Test
    public void sigVerify_WithCertificate_MismatchedAlgorithm_Throws() throws Exception {
        // given
        final String mismatchedAlgorithm = CryptoConstants.SHA384_WITH_RSA;
        final X509Certificate cert = pemToX509Certificate(certInPem);

        // when-then
        assertThrows(InvalidSignatureException.class, () ->
            EcUtils.sigVerify(cert, signaturePayload, matchingSignature,
                mismatchedAlgorithm, CryptoUtils.getBouncyCastleProvider()));
    }

    @ParameterizedTest
    @ValueSource(ints = {47, 48, 49})
    public void toPrivate_ForDifferentKeySizes_Success(int initialKeySize) throws Exception {
        // given
        final byte[] privateBytesAlignedToLen48 = generatePrivateKeyBytesOfInitialSizeAlignedTo48(initialKeySize);

        // when
        PrivateKey result = EcUtils.toPrivate(privateBytesAlignedToLen48, CryptoConstants.ECDH_KEY,
            CryptoConstants.EC_CURVE_SPEC_384, CryptoUtils.getBouncyCastleProvider());

        // then
        assertNotNull(result);
        assertEquals(CryptoConstants.ECDH_KEY, result.getAlgorithm());
        assertThatArrayIsSubarrayOfAnotherArray(result.getEncoded(), privateBytesAlignedToLen48);
    }

    @Test
    public void toPublic_Ec384() throws KeystoreGenericException, InvalidKeySpecException, NoSuchAlgorithmException,
        EcdhKeyPairException {
        // given
        final String curveType = CryptoConstants.EC_CURVE_SPEC_384;
        final KeyPair key = EcUtils.genEc(CryptoUtils.getBouncyCastleProvider(), CryptoConstants.ECDH_KEY, curveType);
        final ECPublicKey publicKey = (ECPublicKey) key.getPublic();
        final byte[] publicKeyBytes = EcUtils.getRawXYBytesFromPubKey(publicKey, 2 * CryptoConstants.SHA384_LEN);

        // when
        PublicKey result = EcUtils.toPublic(publicKeyBytes, CryptoConstants.ECDH_KEY,
            curveType, CryptoUtils.getBouncyCastleProvider());

        // then
        assertNotNull(result);
        assertEquals(CryptoConstants.ECDH_KEY, result.getAlgorithm());
        assertThatArrayIsSubarrayOfAnotherArray(result.getEncoded(), publicKeyBytes);
    }

    @Test
    public void toPublic_Ec256() throws KeystoreGenericException, InvalidKeySpecException, NoSuchAlgorithmException,
        EcdhKeyPairException {
        // given
        final String curveType = CryptoConstants.EC_CURVE_SPEC_256;
        final KeyPair key = EcUtils.genEc(CryptoUtils.getBouncyCastleProvider(), CryptoConstants.ECDH_KEY, curveType);
        final ECPublicKey publicKey = (ECPublicKey) key.getPublic();
        final byte[] publicKeyBytes = EcUtils.getRawXYBytesFromPubKey(publicKey, 2 * CryptoConstants.SHA256_LEN);

        // when
        PublicKey result = EcUtils.toPublic(publicKeyBytes, CryptoConstants.ECDH_KEY,
            curveType, CryptoUtils.getBouncyCastleProvider());

        // then
        assertNotNull(result);
        assertEquals(CryptoConstants.ECDH_KEY, result.getAlgorithm());
        assertThatArrayIsSubarrayOfAnotherArray(result.getEncoded(), publicKeyBytes);
    }

    @Test
    public void toPublic_InvalidKey_Throws() {
        // given
        final String curveType = CryptoConstants.EC_CURVE_SPEC_384;
        final byte[] invalidPublicKeyBytes = new byte[96];

        // when-then
        assertThrows(EcdhKeyPairException.class, () ->
            EcUtils.toPublic(invalidPublicKeyBytes, CryptoConstants.ECDH_KEY,
                curveType, CryptoUtils.getBouncyCastleProvider()));
    }

    @Test
    void generateSha256Fingerprint_Success() throws Exception {
        // given
        int expectedLen = 2 * CryptoConstants.SHA256_LEN;
        final KeyPair keyPair = CryptoUtils.genEcdsaBC(CryptoConstants.EC_CURVE_SPEC_384);

        // when
        final String result = EcUtils.generateSha256Fingerprint(keyPair.getPublic());

        // then
        assertEquals(expectedLen, result.length());
    }

    @SneakyThrows
    private static byte[] generatePrivateKeyBytesOfInitialSizeAlignedTo48(int initialKeySize) {
        byte[] privateBytes;
        do {
            final KeyPair key = CryptoUtils.genEcdhBC();
            privateBytes = EcUtils.getBytesFromPrivKey((ECPrivateKey) key.getPrivate());
        } while (privateBytes.length != initialKeySize);

        return PaddingUtils.alignLeft(privateBytes, 48);
    }
}
