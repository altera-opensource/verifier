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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.command.MailboxCommandLayer;
import com.intel.bkp.command.model.CommandLayer;
import com.intel.bkp.core.properties.DistributionPoint;
import com.intel.bkp.core.properties.Proxy;
import com.intel.bkp.core.properties.TrustStore;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.utils.PathUtils;
import com.intel.bkp.verifier.config.JceSecurityConfiguration;
import com.intel.bkp.verifier.database.SQLiteHelper;
import com.intel.bkp.verifier.exceptions.VerifierKeyNotInitializedException;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.VerifierKeyParams;
import com.intel.bkp.verifier.protocol.sigma.service.VerifierKeyManager;
import com.intel.bkp.verifier.security.X509TrustManagerManager;
import com.intel.bkp.verifier.transport.model.TransportLayer;
import com.intel.bkp.verifier.utils.LibConfigParser;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Getter
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AppContext implements AutoCloseable {

    private static final String CONFIG_FILE_NAME = "config.properties";

    private LibConfig libConfig;
    private CommandLayer commandLayer;
    private ISecurityProvider securityProvider;
    private SQLiteHelper sqLiteHelper;
    private VerifierKeyParams verifierKeyParams;
    private VerifierKeyManager verifierKeyManager;
    private DistributionPointConnector dpConnector;
    private TrustStore trustStore;

    private static AppContext INSTANCE;

    public static AppContext instance() {
        if (INSTANCE == null) {
            log.debug("Initializing AppContext...");
            logAppInfo();
            INSTANCE = initialize();
            logAppConfiguration();
        }
        return INSTANCE;
    }

    static AppContext initialize() {
        final LibConfig libConfig = prepareLibConfig();
        final ISecurityProvider securityProvider = prepareSecurityProvider(libConfig);
        final VerifierKeyParams verifierKeyParams = prepareVerifierKeyParams(libConfig);
        final TrustStore trustStore = prepareTrustStore(libConfig);

        return new AppContext(libConfig, prepareCommandLayer(), securityProvider,
            prepareSqLiteHelper(libConfig), verifierKeyParams,
            prepareVerifierKeyManager(securityProvider, verifierKeyParams.getKeyName()),
            prepareDistributionPointConnector(libConfig, trustStore), trustStore);
    }

    private static void logAppInfo() {
        Package verifierPackage = AppContext.class.getPackage();
        String implementationVersion = verifierPackage.getImplementationVersion();
        String implementationTitle = verifierPackage.getImplementationTitle();
        log.info("Library details: VENDOR: {}, VERSION: {}", implementationTitle, implementationVersion);
    }

    private static void logAppConfiguration() {
        log.debug("Library configuration: {}", INSTANCE.getLibConfig());
    }

    private static LibConfig prepareLibConfig() {
        return new LibConfigParser().parseConfigFile(CONFIG_FILE_NAME);
    }

    private static ISecurityProvider prepareSecurityProvider(LibConfig libConfig) {
        return JceSecurityConfiguration.getSecurityProvider(libConfig.getProviderParams());
    }

    private static VerifierKeyParams prepareVerifierKeyParams(LibConfig libConfig) {
        return libConfig.getVerifierKeyParams();
    }

    private static VerifierKeyManager prepareVerifierKeyManager(ISecurityProvider securityProvider, String keyName) {
        return new VerifierKeyManager(securityProvider, keyName);
    }

    private static MailboxCommandLayer prepareCommandLayer() {
        return new MailboxCommandLayer();
    }

    private static SQLiteHelper prepareSqLiteHelper(LibConfig libConfig) {
        return new SQLiteHelper(libConfig.getDatabaseConfiguration());
    }

    private static TrustStore prepareTrustStore(LibConfig libConfig) {
        return libConfig.getTrustStore();
    }

    private static DistributionPointConnector prepareDistributionPointConnector(LibConfig libConfig,
                                                                                TrustStore trustStore) {
        final Proxy proxy = libConfig.getDistributionPoint().getProxy();
        return new DistributionPointConnector(proxy.getHost(), proxy.getPort(),
            new X509TrustManagerManager(trustStore).getTrustManagers());
    }

    /**
     * Must be called after calling instance() for the first time.
     */
    public void init() {
        if (!verifierKeyManager.initialized()) {
            verifierKeyManager.initialize();
            throw new VerifierKeyNotInitializedException();
        }
    }

    public TransportLayer getTransportLayer() {
        return libConfig.getTransportLayerType().getTransportLayer();
    }

    public String[] getDpTrustedRootHashes() {
        return libConfig.getDistributionPoint().getTrustedRootHash();
    }

    public String getDpPathCer() {
        final DistributionPoint dp = libConfig.getDistributionPoint();
        return PathUtils.buildPath(dp.getMainPath(), dp.getAttestationCertBasePath());
    }

    @Override
    public void close() {
        sqLiteHelper.close();
        try {
            dpConnector.close();
        } catch (Exception e) {
            log.error("Failed to close active DP connections.");
        }
        INSTANCE = null;
    }
}
