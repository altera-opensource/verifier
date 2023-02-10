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
import com.intel.bkp.crypto.KeystoreUtils;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.crypto.exceptions.EncryptionProviderException;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.impl.AesUtils;
import com.intel.bkp.crypto.impl.EcUtils;
import com.intel.bkp.crypto.impl.RsaUtils;
import com.intel.bkp.crypto.rsa.RsaEncryptionProvider;
import dev.failsafe.Failsafe;
import dev.failsafe.FailsafeException;
import dev.failsafe.RetryPolicy;
import dev.failsafe.function.CheckedPredicate;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

@Slf4j
public class JceSecurityProvider implements ISecurityProvider {

    private static final int DELAY_SECONDS = 1;
    private static final int MAX_RETRIES = 3;

    @Getter
    protected Provider provider;

    @Setter
    protected KeyStore keyStore;

    @Getter
    private IKeystoreManager keystoreManager;

    protected SecurityProviderParams securityProviderParams;

    @Getter
    private final ProviderProperties providerProperties;

    @Getter
    private final SecurityProperties securityProperties;

    @Getter
    private final KeyTypesProperties keyTypesProperties;

    private final RsaProperties rsaProperties;
    private final AesProperties aesProperties;
    private final EcProperties ecProperties;

    protected String providerName;
    protected String keyStoreName;
    protected String inputStreamParam;
    private final IKeystoreManagerChooser chooserCallback;

    private final RetryPolicy<Object> retryPolicy = prepareRetryPolicy(Optional.empty());
    private final RetryPolicy<Object> retryPolicyWithResult = prepareRetryPolicy(Optional.of(Objects::isNull));
    private final RetryPolicy<Object> retryPolicyWithBoolean = prepareRetryPolicy(Optional.of(o -> !((boolean) o)));

    private RetryPolicy<Object> prepareRetryPolicy(Optional<CheckedPredicate<Object>> handleResultIfPredicate) {
        final var retryPolicy = RetryPolicy.builder()
            .handle(KeyStoreException.class)
            .withDelay(Duration.ofSeconds(DELAY_SECONDS))
            .withMaxRetries(MAX_RETRIES)
            .abortOn(UnrecoverableKeyException.class)
            .onRetry(e -> reloadKeystore());

        return handleResultIfPredicate
            .map(retryPolicy::handleResultIf)
            .orElse(retryPolicy)
            .build();
    }

    public JceSecurityProvider(SecurityProviderParams params, IKeystoreManagerChooser chooserCallback) {
        this.securityProviderParams = params;
        this.chooserCallback = chooserCallback;
        this.providerProperties = securityProviderParams.getProvider();
        this.securityProperties = securityProviderParams.getSecurity();
        this.keyTypesProperties = securityProviderParams.getKeyTypes();
        rsaProperties = keyTypesProperties.getRsa();
        aesProperties = keyTypesProperties.getAes();
        ecProperties = keyTypesProperties.getEc();
        init();
    }

    private void init() {
        this.initializeFields();
        this.provider = initialize();
        keystoreManager = chooserCallback.getKeystoreManager();
        login();
    }

    private void initializeFields() {
        this.providerName = providerProperties.getName();
        this.keyStoreName = securityProperties.getKeyStoreName();
        this.inputStreamParam = securityProperties.getInputStreamParam();
    }

    private Provider initialize() {
        Optional<Provider> availableProvider = getSystemProvider(this.providerName);
        return availableProvider.orElseThrow(() -> new JceSecurityProviderException(
            String.format("Failed to find system provider: %s", this.providerName)
        ));
    }

    private Optional<Provider> getSystemProvider(String providerName) {
        return Optional.ofNullable(Security.getProvider(providerName));
    }

    public void login() {
        log.trace("Login to keystore: {}", keyStoreName);
        try {
            if (keyStore == null) {
                keyStore = KeyStore.getInstance(keyStoreName, provider);
            }
            keystoreManager.load(keyStore, inputStreamParam, securityProperties.getPassword());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new JceSecurityProviderException("Failed to initialize keystore.", e);
        }
    }

    public boolean checkConnection() {
        return keyStore != null && KeystoreUtils.listSecurityObjects(keyStore) != null;
    }

    private void saveSecureEnclave() {
        log.debug("Saving secure enclave.");
        try {
            String password = securityProperties.getPassword();
            keystoreManager.store(keyStore, inputStreamParam, password);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new JceSecurityProviderException("Failed to store keypair in secure enclave.", e);
        }
    }

    public Object createSecurityObject(String name) {
        return createSecurityObject(name, ecProperties.getSignatureAlgorithm());
    }

    public synchronized Object createSecurityObject(String name, String algorithm) {
        log.debug("Creating security object with name {} and algorithm {}.", name, algorithm);
        final KeyPair kp;
        try {
            kp = EcUtils.genEc(provider, ecProperties.getKeyName(), ecProperties.getCurveSpec384());
            KeystoreUtils.storeKeyWithCertificate(provider, keyStore, kp, name, 40L, algorithm);
            saveSecureEnclave();
            return kp;
        } catch (KeystoreGenericException e) {
            throw new JceSecurityProviderException(e.getMessage(), e);
        }
    }

    public synchronized Object createSecurityObject(SecurityKeyType keyType, String name) {
        log.debug("Creating security object with name {} and type {}.", name, keyType.name());
        try {
            if (SecurityKeyType.RSA == keyType) {
                final KeyPair kp = RsaUtils.genRSA(rsaProperties.getKeyName(), rsaProperties.getKeySize(), provider);
                final String algorithm = rsaProperties.getSignatureAlgorithm();
                KeystoreUtils.storeKeyWithCertificate(provider, keyStore, kp, name, 40L, algorithm);
                saveSecureEnclave();
                return kp;
            } else if (SecurityKeyType.AES == keyType) {
                SecretKey secretKey = AesUtils.genAES(provider, aesProperties.getKeyName(), aesProperties.getKeySize());
                KeystoreUtils.storeSecretKey(keyStore, secretKey, name);
                saveSecureEnclave();
                return secretKey;
            } else {
                final KeyPair kp = EcUtils.genEc(provider, ecProperties.getKeyName(),
                    ecProperties.getCurveSpec384());
                final String algorithm = ecProperties.getSignatureAlgorithm();
                KeystoreUtils.storeKeyWithCertificate(provider, keyStore, kp, name, 40L, algorithm);
                saveSecureEnclave();
                return kp;
            }
        } catch (KeystoreGenericException e) {
            throw new JceSecurityProviderException(e.getMessage(), e);
        }
    }

    public byte[] decryptRSA(String alias, byte[] encryptedData) {
        log.debug("Decrypting RSA data with alias {}.", alias);
        try {
            final Key rsaKey = Failsafe.with(retryPolicy).get(
                () -> keyStore.getKey(alias, "".toCharArray())
            );
            RsaEncryptionProvider rsaEncryptionProvider = new RsaEncryptionProvider(rsaKey, provider,
                rsaProperties.getCipherType());
            return rsaEncryptionProvider.decrypt(encryptedData);
        } catch (FailsafeException | EncryptionProviderException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to decrypt RSA encoded message for key '%s'.", alias), e);
        }
    }

    @Override
    public void importSecretKey(String name, SecretKey secretKey) {
        log.debug("Importing secret key with name {}.", name);
        try {
            KeystoreUtils.storeSecretKey(keyStore, secretKey, name);
            saveSecureEnclave();
        } catch (KeystoreGenericException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to import secret key with alias '%s'.", name), e);
        }
    }

    @Override
    public void importEcKey(String name, PublicKey publicKey, PrivateKey privateKey) {
        log.debug("Importing EC key with name {}.", name);
        try {
            KeystoreUtils.storeKeyWithCertificate(provider, keyStore, publicKey, privateKey,
                name, 40L, ecProperties.getSignatureAlgorithm());
            saveSecureEnclave();
        } catch (KeystoreGenericException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to import EC key with alias '%s'.", name), e);
        }
    }

    public synchronized void deleteSecurityObject(String name) {
        log.debug("Deleting security object with name {}.", name);
        try {
            Failsafe.with(retryPolicy).run(() -> keyStore.deleteEntry(name));
            saveSecureEnclave();
        } catch (FailsafeException e) {
            throw new JceSecurityProviderException(String.format("Failed to delete security object '%1s'.", name), e);
        }
    }

    public synchronized boolean existsSecurityObject(String name) {
        log.debug("Looking for key with name {}.", name);
        try {
            return Failsafe.with(retryPolicyWithBoolean).get(() -> keyStore.isKeyEntry(name));
        } catch (FailsafeException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to check if security object '%1s' exists.", name), e);
        }
    }

    public byte[] getPubKeyFromSecurityObject(String name) {
        log.debug("Getting public key from security object with name {}.", name);
        return Optional.ofNullable(getCertificates(name))
            .filter(certs -> certs.length != 0)
            .map(certificates1 -> certificates1[0])
            .map(Certificate::getPublicKey)
            .map(Key::getEncoded)
            .orElseThrow(() -> new JceSecurityProviderException(
                String.format("Failed to retrieve public key for key '%1s'.", name)));
    }

    private Certificate[] getCertificates(String name) {
        log.debug("Getting certificates from security object with name {}.", name);
        try {
            return Failsafe.with(retryPolicyWithResult).get(() -> keyStore.getCertificateChain(name));
        } catch (FailsafeException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to retrieve certificate for key '%1s'. KeyStore is not initialized.", name), e);
        }
    }

    public byte[] signObject(byte[] content, String name) {
        log.debug("Signing object with name {}.", name);
        try {
            final PrivateKey privateKey = Failsafe.with(retryPolicyWithResult).get(
                () -> (PrivateKey) keyStore.getKey(name, "".toCharArray())
            );
            return EcUtils.signEcData(privateKey, content, ecProperties.getSignatureAlgorithm(),
                provider);
        } catch (FailsafeException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to retrieve key '%1s'. KeyStore may be not initialized.", name), e);
        } catch (KeystoreGenericException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to sign data with private key '%1s'.", name), e);
        }
    }

    public SecretKey getKeyFromSecurityObject(String name) {
        log.debug("Getting secret key from security object with name {}.", name);
        try {
            return Failsafe.with(retryPolicyWithResult)
                .get(() -> (SecretKey) keyStore.getKey(name, "".toCharArray()));
        } catch (FailsafeException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to retrieve SecretKey for alias '%s'.", name), e);
        }
    }

    public PrivateKey getPrivateKeyFromSecurityObject(String name) {
        log.debug("Getting private key from security object with name {}.", name);
        try {
            return Failsafe.with(retryPolicyWithResult)
                .get(() -> (PrivateKey) keyStore.getKey(name, "".toCharArray()));
        } catch (FailsafeException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to retrieve PrivateKey for alias '%s'.", name), e);
        }
    }

    @Override
    public String getAesCipherType() {
        return aesProperties.getCipherType();
    }

    private void reloadKeystore() {
        log.trace("Reloading keystore.");
        login();
    }
}
