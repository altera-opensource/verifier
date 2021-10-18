/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.ext.core.security;

import com.intel.bkp.ext.core.exceptions.JceSecurityProviderException;
import com.intel.bkp.ext.core.security.params.KeyTypesProperties;
import com.intel.bkp.ext.core.security.params.ProviderProperties;
import com.intel.bkp.ext.core.security.params.SecurityProperties;
import com.intel.bkp.ext.core.security.params.crypto.EcProperties;
import com.intel.bkp.ext.crypto.KeystoreUtils;
import com.intel.bkp.ext.crypto.constants.SecurityKeyType;
import com.intel.bkp.ext.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.ext.crypto.impl.EcUtils;
import lombok.Getter;
import lombok.Setter;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.FailsafeException;
import net.jodah.failsafe.RetryPolicy;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

public class JceSecurityProvider implements ISecurityProvider {

    private static final int DELAY_SECONDS = 1;
    private static final int MAX_RETRIES = 3;
    @Getter
    private final ProviderProperties providerProperties;
    @Getter
    private final SecurityProperties securityProperties;
    @Getter
    private final KeyTypesProperties keyTypesProperties;
    private final EcProperties ecProperties;
    private final IKeystoreManagerChooser chooserCallback;
    @Getter
    protected Provider provider;
    @Setter
    protected KeyStore keyStore;
    protected SecurityProviderParams securityProviderParams;
    protected String providerName;
    protected String keyStoreName;
    protected String inputStreamParam;
    @Getter
    private IKeystoreManager keystoreManager;
    private final RetryPolicy<Object> retryPolicy = new RetryPolicy<>()
        .handle(KeyStoreException.class)
        .withDelay(Duration.ofSeconds(DELAY_SECONDS))
        .withMaxRetries(MAX_RETRIES)
        .abortOn(UnrecoverableKeyException.class)
        .onRetry(e -> reloadKeystore());

    private final RetryPolicy<Object> retryPolicyWithResult = new RetryPolicy<>()
        .handle(KeyStoreException.class)
        .handleResultIf(Objects::isNull)
        .withDelay(Duration.ofSeconds(DELAY_SECONDS))
        .withMaxRetries(MAX_RETRIES)
        .abortOn(UnrecoverableKeyException.class)
        .onRetry(e -> reloadKeystore());

    public JceSecurityProvider(SecurityProviderParams params, IKeystoreManagerChooser chooserCallback) {
        this.securityProviderParams = params;
        this.chooserCallback = chooserCallback;
        this.providerProperties = securityProviderParams.getProvider();
        this.securityProperties = securityProviderParams.getSecurity();
        this.keyTypesProperties = securityProviderParams.getKeyTypes();
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
        try {
            if (keyStore == null) {
                keyStore = KeyStore.getInstance(keyStoreName, provider);
            }
            keystoreManager.load(keyStore, inputStreamParam, securityProperties.getPassword());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new JceSecurityProviderException("Failed to initialize keystore.", e);
        }
    }

    private void saveSecureEnclave() {
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
        try {
            if (SecurityKeyType.EC == keyType) {
                final KeyPair kp = EcUtils.genEc(provider, ecProperties.getKeyName(),
                    ecProperties.getCurveSpec384());
                final String algorithm = ecProperties.getSignatureAlgorithm();
                KeystoreUtils.storeKeyWithCertificate(provider, keyStore, kp, name, 40L, algorithm);
                saveSecureEnclave();
                return kp;
            } else {
                throw new JceSecurityProviderException("Unsupported operation.");
            }
        } catch (KeystoreGenericException e) {
            throw new JceSecurityProviderException(e.getMessage(), e);
        }
    }

    public synchronized void deleteSecurityObject(String name) {
        try {
            Failsafe.with(retryPolicy).run(() -> keyStore.deleteEntry(name));
            saveSecureEnclave();
        } catch (FailsafeException e) {
            throw new JceSecurityProviderException(String.format("Failed to delete security object '%1s'.", name), e);
        }
    }

    public synchronized boolean existsSecurityObject(String name) {
        try {
            return Failsafe.with(retryPolicyWithResult).get(() -> keyStore.isKeyEntry(name));
        } catch (FailsafeException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to check if security object '%1s' exists.", name), e);
        }
    }

    public byte[] getPubKeyFromSecurityObject(String name) {
        return Optional.ofNullable(getCertificates(name))
            .filter(certs -> certs.length != 0)
            .map(certificates1 -> certificates1[0])
            .map(Certificate::getPublicKey)
            .map(Key::getEncoded)
            .orElseThrow(() -> new JceSecurityProviderException(
                String.format("Failed to retrieve public key for key '%1s'.", name)));
    }

    private Certificate[] getCertificates(String name) {
        try {
            return Failsafe.with(retryPolicyWithResult).get(() -> keyStore.getCertificateChain(name));
        } catch (FailsafeException e) {
            throw new JceSecurityProviderException(
                String.format("Failed to retrieve certificate for key '%1s'. KeyStore is not initialized.", name), e);
        }
    }

    public byte[] signObject(byte[] content, String name) {
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

    private void reloadKeystore() {
        login();
    }
}
