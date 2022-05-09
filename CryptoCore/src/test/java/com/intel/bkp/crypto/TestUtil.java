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

package com.intel.bkp.crypto;

import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.crypto.exceptions.X509CrlParsingException;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilder;
import com.intel.bkp.crypto.x509.generation.X509CertificateBuilderParams;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Assertions;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import static com.intel.bkp.crypto.CryptoUtils.getBouncyCastleProvider;
import static com.intel.bkp.crypto.constants.CryptoConstants.AES_KEY;
import static com.intel.bkp.crypto.constants.CryptoConstants.AES_KEY_SIZE;
import static com.intel.bkp.crypto.constants.CryptoConstants.ECDSA_KEY;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_384;
import static com.intel.bkp.crypto.constants.CryptoConstants.RSA_KEY;
import static com.intel.bkp.crypto.constants.CryptoConstants.RSA_KEY_SIZE;
import static com.intel.bkp.crypto.impl.AesUtils.genAES;
import static com.intel.bkp.crypto.impl.EcUtils.genEc;
import static com.intel.bkp.crypto.impl.EcUtils.signEcData;
import static com.intel.bkp.crypto.impl.RsaUtils.genRSA;
import static com.intel.bkp.crypto.x509.parsing.X509CertificateParser.toX509Certificate;
import static com.intel.bkp.crypto.x509.parsing.X509CrlParser.toX509Crl;

/**
 * Utility class for testing.
 */
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
public class TestUtil {

    public static KeyPair genEcKeys() throws KeystoreGenericException {
        return genEc(getBouncyCastleProvider(), ECDSA_KEY, EC_CURVE_SPEC_384);
    }

    public static KeyPair genRsaKeys() throws KeystoreGenericException {
        return genRSA(RSA_KEY, RSA_KEY_SIZE, getBouncyCastleProvider());
    }

    public static byte[] signEc(byte[] msg, PrivateKey priv, String sigAlgorithmName)
        throws KeystoreGenericException {
        return signEcData(priv, msg, sigAlgorithmName, getBouncyCastleProvider());
    }

    public static byte[] getRandom(int size) {
        byte[] bytes = new byte[size];
        new Random().nextBytes(bytes);
        return bytes;
    }

    public static void assertThatArrayIsSubarrayOfAnotherArray(byte[] array, byte[] subarrayToVerify) {
        List<Byte> outerArray = Arrays.asList(ArrayUtils.toObject(array));
        List<Byte> innerArray = Arrays.asList(ArrayUtils.toObject(subarrayToVerify));
        Assertions.assertTrue(Collections.indexOfSubList(outerArray, innerArray) != -1);
    }

    public static SecretKey generateAesKey() throws KeystoreGenericException {
        return genAES(getBouncyCastleProvider(), AES_KEY, AES_KEY_SIZE);
    }

    public static PrivateKey getEcPrivateKeyFromPem(String privateKeyInPem) throws NoSuchAlgorithmException,
        InvalidKeySpecException {

        byte[] encoded = getBytesFromPemString(privateKeyInPem);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }

    public static PublicKey getEcPublicKeyFromPem(String publicKeyInPem) throws NoSuchAlgorithmException,
        InvalidKeySpecException {

        byte[] encoded = getBytesFromPemString(publicKeyInPem);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }

    private static byte[] getBytesFromPemString(String pem) {
        String tagPattern = "-----\\b(BEGIN|END)\\b .*?-----";
        String content = pem
            .replaceAll(System.lineSeparator(), "")
            .replaceAll(tagPattern, "");

        return Base64.decodeBase64(content);
    }

    public static String getResourceAsString(String pathToFolderInResources, String filename) throws IOException {
        return IOUtils.toString(
            TestUtil.class.getResourceAsStream(pathToFolderInResources + filename),
            StandardCharsets.UTF_8
        );
    }

    public static byte[] getResourceAsBytes(String pathToFolderInResources, String filename) throws IOException {
        return IOUtils.toByteArray(
            TestUtil.class.getResourceAsStream(pathToFolderInResources + filename)
        );
    }

    public static X509Certificate loadCertificate(String filename) throws IOException, X509CertificateParsingException {
        final byte[] fileContent = getResourceAsBytes("/certs/", filename);
        return toX509Certificate(fileContent);
    }

    public static X509CRL loadCrl(String filename) throws IOException, X509CrlParsingException {
        final byte[] fileContent = getResourceAsBytes("/certs/", filename);
        return toX509Crl(fileContent);
    }

    @SneakyThrows
    public static X509Certificate genSelfSignedCert(KeyPair keyPair) {
        final var params = new X509CertificateBuilderParams(keyPair.getPublic());

        return new X509CertificateBuilder(params)
            .sign(keyPair.getPrivate());
    }
}
