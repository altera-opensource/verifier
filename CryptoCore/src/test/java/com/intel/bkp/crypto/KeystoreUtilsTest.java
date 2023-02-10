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

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.impl.AesUtils;
import com.intel.bkp.crypto.impl.EcUtils;
import com.intel.bkp.crypto.provider.TestProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Provider;
import java.util.Enumeration;

class KeystoreUtilsTest {

    private static final String providerName = "test-provider";
    private static final String keyStoreName = "TestKeyStore";
    private static final String keyStorePassword = "password";
    private static final String testKeyAlias = "testAlias";
    private static final String testKeyAliasWrong = "testKeyAliasWrong";

    private static final String providerHelperPath = "com.intel.bkp.crypto.provider";
    private static final String providerHelperClassAES = providerHelperPath + ".AES";
    private static final String providerHelperClassKeyStore = providerHelperPath + "." + keyStoreName;
    private static final String providerHelperClassEC = providerHelperPath + ".EC";
    private static final String providerHelperClassECDSA = providerHelperPath + ".Sha384WithEcdsa";

    private Provider provider;

    @BeforeEach
    void setup() {
        provider = new TestProvider(providerName, "1.0", "info");
    }

    @Test
    void storeSecretKey_storesSecretKeyInKeyStore() throws Exception {
        //given
        final KeyStore keyStore = prepareKeyStore(true);
        final SecretKey secretKey = prepareAesKey();

        //when
        KeystoreUtils.storeSecretKey(keyStore, secretKey, testKeyAlias);

        //then
        final Key testKey = keyStore.getKey(testKeyAlias, "".toCharArray());
        Assertions.assertNotNull(testKey);
    }

    @Test
    void storeSecretKey_throwsExceptionDueToKeyStoreNotInitialized() throws Exception {
        //given
        final KeyStore keyStore = prepareKeyStore(false);
        final SecretKey secretKey = prepareAesKey();

        Assertions.assertThrows(KeystoreGenericException.class, () -> {
            KeystoreUtils.storeSecretKey(keyStore, secretKey, testKeyAlias);
        });
    }

    @Test
    void listSecurityObjects_returnsListOfAliases() throws Exception {
        //given
        final KeyStore keyStore = prepareKeyStore(true);
        final SecretKey secretKey = prepareAesKey();
        KeystoreUtils.storeSecretKey(keyStore, secretKey, testKeyAlias);

        //when
        final Enumeration<String> aliasesList = KeystoreUtils.listSecurityObjects(keyStore);

        //then
        Assertions.assertNotNull(aliasesList);
        Assertions.assertTrue(aliasesList.hasMoreElements());
        Assertions.assertEquals(testKeyAlias, aliasesList.nextElement());
    }

    @Test
    void listSecurityObjects_returnsNullDueToKeyStoreNotInitialized() throws Exception {
        //given
        final KeyStore keyStore = prepareKeyStore(false);

        //when
        final Enumeration<String> aliasesList = KeystoreUtils.listSecurityObjects(keyStore);

        //then
        Assertions.assertNull(aliasesList);
    }

    @Test
    void storeKeyWithCertificate_storesKeyPairWithCertificate() throws Exception {
        //given
        KeyStore keyStore = prepareKeyStore(true);
        final KeyPair keyPair = prepareEcKey();

        //when-then
        Assertions.assertDoesNotThrow(() -> {
            KeystoreUtils.storeKeyWithCertificate(
                provider, keyStore, keyPair, testKeyAlias, 1L, CryptoConstants.SHA384_WITH_ECDSA
            );
        });
    }

    @Test
    void storeKeyWithCertificate_throwsExceptionDueToUnknownReason() throws Exception {
        //given
        KeyStore keyStore = prepareKeyStore(true);
        final KeyPair keyPair = prepareEcKey();

        Assertions.assertThrows(KeystoreGenericException.class, () -> {
            KeystoreUtils.storeKeyWithCertificate(
                provider, keyStore, keyPair, testKeyAliasWrong, 1L, CryptoConstants.SHA384_WITH_ECDSA
            );
        });
    }

    @Test
    void storeKeyWithCertificate_throwsExceptionDueToKeyStoreNotInitialized() throws Exception {
        //given
        KeyStore keyStore = prepareKeyStore(false);
        final KeyPair keyPair = prepareEcKey();

        Assertions.assertThrows(KeystoreGenericException.class, () -> {
            KeystoreUtils.storeKeyWithCertificate(
                provider, keyStore, keyPair, testKeyAlias, 1L, CryptoConstants.SHA384_WITH_ECDSA
            );
        });
    }

    private SecretKey prepareAesKey() throws KeystoreGenericException {
        provider.setProperty("KeyGenerator.AES", providerHelperClassAES);
        return AesUtils.genAES(provider, CryptoConstants.AES_KEY, CryptoConstants.AES_KEY_SIZE);
    }

    private KeyPair prepareEcKey() throws KeystoreGenericException {
        provider.setProperty("KeyPairGenerator.EC", providerHelperClassEC);
        provider.setProperty("Signature.Sha384WithEcdsa", providerHelperClassECDSA);
        return EcUtils.genEc(provider, CryptoConstants.EC_KEY, CryptoConstants.EC_CURVE_SPEC_384);
    }

    private KeyStore prepareKeyStore(boolean loadKeyStore) throws Exception {
        provider.setProperty("KeyStore." + keyStoreName, providerHelperClassKeyStore);

        KeyStore keyStore = KeyStore.getInstance(keyStoreName, provider);
        if (loadKeyStore) {
            keyStore.load(null, keyStorePassword.toCharArray());
        }

        return keyStore;
    }
}
