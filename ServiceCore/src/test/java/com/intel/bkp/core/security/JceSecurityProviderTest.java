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

package com.intel.bkp.core.security;

import com.intel.bkp.core.exceptions.JceSecurityProviderException;
import com.intel.bkp.core.security.params.KeyTypesProperties;
import com.intel.bkp.core.security.params.ProviderProperties;
import com.intel.bkp.core.security.params.SecurityProperties;
import com.intel.bkp.core.security.params.crypto.AesProperties;
import com.intel.bkp.core.security.params.crypto.EcProperties;
import com.intel.bkp.core.security.params.crypto.RsaProperties;
import com.intel.bkp.core.utils.provider.TestKeyStore;
import com.intel.bkp.core.utils.provider.TestProvider;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.KeystoreUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.impl.AesUtils;
import com.intel.bkp.crypto.impl.EcUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the JceSecurityProvider class.
 *
 * @see JceSecurityProvider
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
class JceSecurityProviderTest {

    @Mock
    private SecurityProviderParams securityProviderParams;

    @Mock
    private ProviderProperties providerProperties;

    @Mock
    private SecurityProperties securityProperties;

    @Mock
    private KeyTypesProperties keyTypesProperties;

    @Mock
    private RsaProperties rsaProperties;

    @Mock
    private AesProperties aesProperties;

    @Mock
    private EcProperties ecProperties;

    @Mock
    private IKeystoreManagerChooser keystoreManagerChooser;

    private JceSecurityProvider securityService;

    private static Provider provider = prepareProvider();

    private static final String providerName = "test-provider";
    private static final String keyStoreName = "TestKeyStore";
    private static final String keyStorePassword = "password";
    private static final String testKeyAliasPositive = "testAlias";
    private static final String testKeyAliasNegative = "testKeyAliasWrong";
    private static final String testKeyAliasWrongNullPubKey = "testKeyAliasWrongNullPubKey";
    private static final String testKeyAliasWrongNullChain = "wrongAliasNullChain";
    private static final String testKeyAliasWrongNullCertificateInChain = "testKeyAliasWrongNullCertificateInChain";
    private static final String testKeyAliasWrongEmptyCertificateChain = "testKeyAliasWrongEmptyCertificateChain";

    private static final String providerHelperPath = "com.intel.bkp.core.utils.provider";
    private static final String providerHelperClassKeyStore = providerHelperPath + "." + keyStoreName;
    private static final String providerHelperClassEC = providerHelperPath + ".EC";
    private static final String providerHelperClassAES = providerHelperPath + ".AES";
    private static final String providerHelperClassRSA = providerHelperPath + ".RSA";
    private static final String providerHelperClassECDSA = providerHelperPath + ".Sha384WithEcdsa";
    private static final String providerHelperClassSHA384WITHRSA = providerHelperPath + ".SHA384withRSA";

    private static class TestKeystoreManager implements IKeystoreManager {

        @Override
        public void load(KeyStore keyStore, String inputStreamParam, String password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
            keyStore.load(null, password.toCharArray());
        }

        @Override
        public void store(KeyStore keyStore, String inputStreamParam, String password) {
        }
    }

    @BeforeAll
    static void setUp() {
        Security.addProvider(provider);
    }

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);

        when(securityProviderParams.getProvider()).thenReturn(providerProperties);
        when(providerProperties.getName()).thenReturn(providerName);
        when(securityProviderParams.getSecurity()).thenReturn(securityProperties);
        when(securityProviderParams.getKeyTypes()).thenReturn(keyTypesProperties);
        when(securityProperties.getKeyStoreName()).thenReturn(keyStoreName);
        when(securityProperties.getPassword()).thenReturn(TestKeyStore.password);
        when(securityProperties.getInputStreamParam()).thenReturn("/tmp/unit-test-keystore.jks");
        when(keystoreManagerChooser.getKeystoreManager()).thenReturn(new TestKeystoreManager());

        when(keyTypesProperties.getEc()).thenReturn(ecProperties);
        when(ecProperties.getKeyName()).thenReturn(CryptoConstants.ECDSA_KEY);
        when(ecProperties.getCurveSpec384()).thenReturn(CryptoConstants.EC_CURVE_SPEC_384);
        when(ecProperties.getSignatureAlgorithm()).thenReturn(CryptoConstants.SHA384_WITH_ECDSA);

        when(keyTypesProperties.getRsa()).thenReturn(rsaProperties);
        when(rsaProperties.getKeyName()).thenReturn(CryptoConstants.RSA_KEY);
        when(rsaProperties.getKeySize()).thenReturn(CryptoConstants.RSA_KEY_SIZE);
        when(rsaProperties.getCipherType()).thenReturn(CryptoConstants.RSA_CIPHER_TYPE);
        when(rsaProperties.getSignatureAlgorithm()).thenReturn(CryptoConstants.SHA384_WITH_RSA);

        when(keyTypesProperties.getAes()).thenReturn(aesProperties);
        when(aesProperties.getKeyName()).thenReturn(CryptoConstants.AES_KEY);
        when(aesProperties.getKeySize()).thenReturn(CryptoConstants.AES_KEY_SIZE);
        when(aesProperties.getCipherType()).thenReturn(CryptoConstants.AES_CIPHER_TYPE);

        securityService = new JceSecurityProvider(securityProviderParams, keystoreManagerChooser);
    }

    private static Provider prepareProvider() {
        Provider provider = new TestProvider(providerName, "1.0", "info");
        provider.setProperty("KeyPairGenerator.EC", providerHelperClassEC);
        provider.setProperty("Signature.Sha384WithEcdsa", providerHelperClassECDSA);
        provider.setProperty("Signature.SHA384withRSA", providerHelperClassSHA384WITHRSA);
        provider.setProperty("KeyGenerator.AES", providerHelperClassAES);
        provider.setProperty("KeyPairGenerator.RSA", providerHelperClassRSA);
        provider.setProperty("KeyStore." + keyStoreName, providerHelperClassKeyStore);
        return provider;
    }

    @Test
    void login_Success() throws Exception {
        // given
        prepareKeyStore(false);

        // when
        securityService.login();

        // then
        Assertions.assertTrue(securityService.checkConnection());
    }

    @Test
    void login_throwsExceptionDueToInvalidPassword() throws Exception {
        // given
        when(securityProperties.getPassword()).thenReturn("test");
        prepareKeyStore(false);

        Assertions.assertThrows(JceSecurityProviderException.class, () -> securityService.login());
    }

    @Test
    void checkConnection_returnsFalseDueToNullKeyStore() {
        // given
        securityService.setKeyStore(null);

        // when
        final boolean result = securityService.checkConnection();

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void createSecurityObject_returnsEcKeyPair() throws Exception {
        // given
        prepareEcKey(false);
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        // when
        final Object securityObject = securityService.createSecurityObject(testKeyAliasPositive);

        // then
        Assertions.assertNotNull(securityObject);
    }

    @Test
    void createSecurityObject_WithKeyType_returnsRSAKey() throws Exception {
        // given
        prepareEcKey(false);
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        // when
        final Object secObj = securityService.createSecurityObject(SecurityKeyType.RSA, testKeyAliasPositive);

        // then
        Assertions.assertNotNull(secObj);
    }

    @Test
    void createSecurityObject_WithKeyType_returnsAESKey() throws Exception {
        // given
        prepareEcKey(false);
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        // when
        final Object secObj = securityService.createSecurityObject(SecurityKeyType.AES256, testKeyAliasPositive);

        // then
        Assertions.assertNotNull(secObj);
    }

    @Test
    void createSecurityObject_WithKeyType_returnsEcKeyPair() throws Exception {
        // given
        prepareEcKey(false);
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        // when
        final Object securityObject = securityService.createSecurityObject(SecurityKeyType.EC, testKeyAliasPositive);

        // then
        Assertions.assertNotNull(securityObject);
    }

    @Test
    void decryptRSA_ThrowsException() throws Exception {
        // given
        prepareEcKey(false);
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.decryptRSA(testKeyAliasPositive, "test".getBytes()));
    }

    @Test
    void deleteSecurityObject_deletesObject() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        // when
        securityService.deleteSecurityObject(testKeyAliasPositive);

        // then
        Mockito.verify(securityProperties, times(2)).getPassword();
    }

    @Test
    void deleteSecurityObject_throwsExceptionDueToUnknownReason() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(false);
        securityService.setKeyStore(keyStore);
        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.deleteSecurityObject(testKeyAliasNegative));
    }

    @Test
    void existsSecurityObject_returnsTrue() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        // when
        final boolean result = securityService.existsSecurityObject(testKeyAliasPositive);

        // then
        Assertions.assertTrue(result);
    }

    @Test
    void importSecretKey_Success() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);
        SecretKey secretKey = CryptoUtils.genAesBC();

        // when
        securityService.importSecretKey(testKeyAliasPositive, secretKey);

        // then
        SecretKey result = (SecretKey)keyStore.getKey(testKeyAliasPositive, "".toCharArray());
        Assertions.assertEquals(secretKey, result);
    }

    @Test
    void getPubKeyFromSecurityObject_returnsPubKey() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        // when
        final byte[] pubKeyFromSecurityObject = securityService.getPubKeyFromSecurityObject(testKeyAliasPositive);

        // then
        Assertions.assertNotNull(pubKeyFromSecurityObject);
        Assertions.assertEquals(testKeyAliasPositive, new String(pubKeyFromSecurityObject));
    }

    @Test
    void getPubKeyFromSecurityObject_throwsExceptionDueToNullCertificateInChain() throws Exception {
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.getPubKeyFromSecurityObject(testKeyAliasWrongNullCertificateInChain));
    }

    @Test
    void getPubKeyFromSecurityObject_throwsExceptionDueToNullCertificateChain() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.getPubKeyFromSecurityObject(testKeyAliasWrongNullChain));
    }

    @Test
    void getPubKeyFromSecurityObject_throwsExceptionDueToEmptyCertificateChain() throws Exception {
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.getPubKeyFromSecurityObject(testKeyAliasWrongEmptyCertificateChain));
    }

    @Test
    void getPubKeyFromSecurityObject_throwsExceptionDueToNullPublicKey() throws Exception {
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);

        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.getPubKeyFromSecurityObject(testKeyAliasWrongNullPubKey));
    }

    @Test
    void signObject_ReturnsSignature() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        final KeyPair keyPair = prepareEcKey(true);
        assert keyPair != null;
        KeystoreUtils.storeKeyWithCertificate(securityService.getProvider(), keyStore, keyPair,
            testKeyAliasPositive, 1L, CryptoConstants.SHA384_WITH_ECDSA);
        securityService.setKeyStore(keyStore);
        final byte[] content = "content".getBytes();

        // when
        byte[] signature = securityService.signObject(content, testKeyAliasPositive);

        // then
        Assertions.assertNotNull(signature);
    }

    @Test
    void signObject_throwsExceptionDueToKeyStoreNotInitialized() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(false);
        securityService.setKeyStore(keyStore);
        final byte[] content = "content".getBytes();

        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.signObject(content, testKeyAliasPositive));
    }

    @Test
    void signObject_throwsExceptionDueToUnrecoverableKey() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);
        final byte[] content = "content".getBytes();

        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.signObject(content, testKeyAliasNegative));
    }

    @Test
    void signObject_throwsExceptionDueToNoAlgorithm() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        securityService.setKeyStore(keyStore);
        final byte[] content = "content".getBytes();

        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.signObject(content, testKeyAliasPositive));
    }

    @Test
    void signObject_throwsExceptionDueToInvalidKey() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        prepareEcKey(false);
        securityService.setKeyStore(keyStore);
        final byte[] content = "content".getBytes();

        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.signObject(content, testKeyAliasPositive));
    }

    @Test
    void signObject_throwsExceptionDueToContentError() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        final KeyPair keyPair = prepareEcKey(true);
        assert keyPair != null;
        KeystoreUtils.storeKeyWithCertificate(securityService.getProvider(), keyStore, keyPair,
            testKeyAliasPositive, 1L, CryptoConstants.SHA384_WITH_ECDSA);
        securityService.setKeyStore(keyStore);
        final byte[] content = "error_content".getBytes();

        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.signObject(content, testKeyAliasPositive));
    }

    @Test
    void getKeyFromSecurityObject_WithMissingKeyObject_Success() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        SecretKey secretKey = AesUtils.genAES(provider, CryptoConstants.AES_KEY, CryptoConstants.AES_KEY_SIZE);;
        KeystoreUtils.storeSecretKey(keyStore, secretKey, testKeyAliasPositive);
        securityService.setKeyStore(keyStore);

        // when
        final SecretKey securityObject = securityService.getKeyFromSecurityObject(testKeyAliasPositive);

        // then
        Assertions.assertNotNull(securityObject);
    }

    @Test
    void getKeyFromSecurityObject_WithMissingKeyObject_ThrowsException() {
        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.getKeyFromSecurityObject("test"));
    }

    @Test
    void getPrivateKeyFromSecurityObject_WithMissingKeyObject_Success() throws Exception {
        // given
        KeyStore keyStore = prepareKeyStore(true);
        final KeyPair keyPair = prepareEcKey(true);
        assert keyPair != null;
        KeystoreUtils.storeKeyWithCertificate(securityService.getProvider(), keyStore, keyPair,
            testKeyAliasPositive, 1L, CryptoConstants.SHA384_WITH_ECDSA);
        securityService.setKeyStore(keyStore);

        // when
        final PrivateKey securityObject = securityService.getPrivateKeyFromSecurityObject(testKeyAliasPositive);

        // then
        Assertions.assertNotNull(securityObject);
    }

    @Test
    void getPrivateKeyFromSecurityObject_WithMissingKeyObject_ThrowsException() {
        Assertions.assertThrows(JceSecurityProviderException.class,
            () -> securityService.getPrivateKeyFromSecurityObject("test"));
    }

    private KeyPair prepareEcKey(boolean generateKey) throws KeystoreGenericException {
        Provider provider = securityService.getProvider();

        if (generateKey) {
            return EcUtils.genEc(provider, CryptoConstants.ECDSA_KEY, CryptoConstants.EC_CURVE_SPEC_384);
        } else {
            return null;
        }
    }

    private KeyStore prepareKeyStore(boolean loadKeyStore) throws Exception {
        Provider provider = securityService.getProvider();
        KeyStore keyStore = KeyStore.getInstance(keyStoreName, provider);
        if (loadKeyStore) {
            keyStore.load(null, keyStorePassword.toCharArray());
        }
        return keyStore;
    }
}
