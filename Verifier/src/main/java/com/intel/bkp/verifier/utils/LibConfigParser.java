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

package com.intel.bkp.verifier.utils;

import com.intel.bkp.core.properties.DistributionPoint;
import com.intel.bkp.core.properties.Proxy;
import com.intel.bkp.core.properties.TrustedRootHash;
import com.intel.bkp.core.security.SecurityProviderParams;
import com.intel.bkp.core.security.SecurityProviderParamsSetter;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.model.AttestationCertificateFlow;
import com.intel.bkp.verifier.model.DatabaseConfiguration;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.LibSpdmParams;
import com.intel.bkp.verifier.model.TransportLayerType;
import com.intel.bkp.verifier.model.VerifierKeyParams;
import com.intel.bkp.verifier.model.VerifierRootQkyChain;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;
import java.util.Properties;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static com.intel.bkp.verifier.config.Properties.DATABASE_CONFIGURATION_GROUP;
import static com.intel.bkp.verifier.config.Properties.DISTRIBUTION_POINT_DICE_TRUSTED_ROOT;
import static com.intel.bkp.verifier.config.Properties.DISTRIBUTION_POINT_GROUP;
import static com.intel.bkp.verifier.config.Properties.DISTRIBUTION_POINT_PATH_CER;
import static com.intel.bkp.verifier.config.Properties.DISTRIBUTION_POINT_PROXY_HOST;
import static com.intel.bkp.verifier.config.Properties.DISTRIBUTION_POINT_PROXY_PORT;
import static com.intel.bkp.verifier.config.Properties.DISTRIBUTION_POINT_S10_TRUSTED_ROOT;
import static com.intel.bkp.verifier.config.Properties.EC_GROUP;
import static com.intel.bkp.verifier.config.Properties.KEY_TYPES_GROUP;
import static com.intel.bkp.verifier.config.Properties.LIB_SPDM_CERTIFICATES_EFUSE_UDS_SLOT_ID;
import static com.intel.bkp.verifier.config.Properties.LIB_SPDM_CT_EXPONENT;
import static com.intel.bkp.verifier.config.Properties.LIB_SPDM_MEASUREMENTS_REQUEST_SIGNATURE;
import static com.intel.bkp.verifier.config.Properties.LIB_SPDM_PARAMS_GROUP;
import static com.intel.bkp.verifier.config.Properties.LIB_SPDM_WRAPPER_LIBRARY_PATH;
import static com.intel.bkp.verifier.config.Properties.ONLY_EFUSE_UDS;
import static com.intel.bkp.verifier.config.Properties.PROVIDER_GROUP;
import static com.intel.bkp.verifier.config.Properties.PROVIDER_PARAMS_GROUP;
import static com.intel.bkp.verifier.config.Properties.PROXY_GROUP;
import static com.intel.bkp.verifier.config.Properties.RUN_GP_ATTESTATION;
import static com.intel.bkp.verifier.config.Properties.SECURITY_GROUP;
import static com.intel.bkp.verifier.config.Properties.TEST_MODE_SECRETS;
import static com.intel.bkp.verifier.config.Properties.TRANSPORT_LAYER_TYPE;
import static com.intel.bkp.verifier.config.Properties.TRUSTED_ROOT_HASH_GROUP;
import static com.intel.bkp.verifier.config.Properties.VERIFIER_KEY_CHAIN_GROUP;
import static com.intel.bkp.verifier.config.Properties.VERIFIER_KEY_PARAMS_GROUP;
import static com.intel.bkp.verifier.config.Properties.VERIFIER_KEY_PARAMS_KEY_NAME;
import static com.intel.bkp.verifier.config.Properties.VERIFIER_KEY_PARAMS_MULTI_ROOT_QKY_CHAIN_PATH;
import static com.intel.bkp.verifier.config.Properties.VERIFIER_KEY_PARAMS_SINGLE_ROOT_QKY_CHAIN_PATH;

@Slf4j
@NoArgsConstructor
public class LibConfigParser {

    private static final String VERIFIER_SECURITY_PROVIDER_PASSWORD = "VERIFIER_SECURITY_PROVIDER_PASSWORD";
    static final int DEFAULT_LIB_SPDM_CERTIFICATES_EFUSE_UDS_SLOT_ID = 0x00;
    static final int DEFAULT_LIB_SPDM_CT_EXPONENT = 0x0E;

    public LibConfig parseConfigFile(String configFileName) {
        final SchemaParams prop = new SchemaParams();

        try {
            final Path externalFilepath = prepareExternalFilepath(configFileName);
            if (Files.exists(externalFilepath) && !Files.isDirectory(externalFilepath)) {
                tryLoadFromExternalSource(externalFilepath, prop);
                return getPropValues(prop);
            }
        } catch (FileNotFoundException | URISyntaxException e) {
            log.debug("External config file not available: {}", e.getMessage());
        }

        try {
            loadFromClassPath(configFileName, prop);
            return getPropValues(prop);
        } catch (FileNotFoundException e) {
            throw new InternalLibraryException("Failed to find config file.", e);
        }
    }

    private Path prepareExternalFilepath(String configFileName) throws URISyntaxException {
        final Path jarDirectory = getDirectory();
        return Path.of(jarDirectory.toString(), configFileName);
    }

    Path getDirectory() throws URISyntaxException {
        return Path.of(getClass().getProtectionDomain().getCodeSource().getLocation().toURI())
            .getParent();
    }

    private LibConfig getPropValues(SchemaParams prop) {
        final LibConfig appConfig = new LibConfig();
        appConfig.setTransportLayerType(getTransportLayerType(prop));
        appConfig.setAttestationCertificateFlow(getAttestationCertificateFlow(prop));
        appConfig.setDistributionPoint(getDistributionPoint(prop));
        appConfig.setVerifierKeyParams(getVerifierKeyParams(prop));
        appConfig.setLibSpdmParams(getLibSpdmParams(prop));
        appConfig.setDatabaseConfiguration(getDatabaseConfiguration(prop));
        appConfig.setProviderParams(getProviderParams(prop));
        appConfig.setRunGpAttestation(getRunGpAttestation(prop));
        appConfig.setTestModeSecrets(getTestModeSecrets(prop));
        return appConfig;
    }

    private TransportLayerType getTransportLayerType(SchemaParams prop) {
        try {
            return TransportLayerType.valueOf(prop.getProperty(TRANSPORT_LAYER_TYPE));
        } catch (IllegalArgumentException e) {
            final String transportTypes = Arrays.stream(TransportLayerType.values())
                .map(Enum::name)
                .collect(Collectors.joining(","));
            throw new IllegalArgumentException("Transport layer type is not valid. Use available: " + transportTypes);
        }
    }

    private AttestationCertificateFlow getAttestationCertificateFlow(SchemaParams prop) {
        return new AttestationCertificateFlow(
            Optional.ofNullable(prop.getProperty(ONLY_EFUSE_UDS))
                .map(Boolean::valueOf)
                .orElse(false)
        );
    }

    private DistributionPoint getDistributionPoint(SchemaParams prop) {
        final TrustedRootHash trustedRootHash = new TrustedRootHash(
            Optional.ofNullable(prop.getPropertyGroup(DISTRIBUTION_POINT_S10_TRUSTED_ROOT,
                    DISTRIBUTION_POINT_GROUP, TRUSTED_ROOT_HASH_GROUP))
                .orElse(""),
            Optional.ofNullable(prop.getPropertyGroup(DISTRIBUTION_POINT_DICE_TRUSTED_ROOT,
                    DISTRIBUTION_POINT_GROUP, TRUSTED_ROOT_HASH_GROUP))
                .orElse("")
        );

        final Proxy proxy = new Proxy(
            prop.getPropertyGroup(DISTRIBUTION_POINT_PROXY_HOST,
                DISTRIBUTION_POINT_GROUP, PROXY_GROUP),
            Optional.ofNullable(prop.getPropertyGroup(DISTRIBUTION_POINT_PROXY_PORT,
                    DISTRIBUTION_POINT_GROUP, PROXY_GROUP))
                .filter(Predicate.not(StringUtils::isBlank))
                .map(Integer::valueOf)
                .orElse(null));

        return new DistributionPoint(
            prop.getPropertyGroup(DISTRIBUTION_POINT_PATH_CER, DISTRIBUTION_POINT_GROUP),
            trustedRootHash,
            proxy
        );
    }

    private VerifierKeyParams getVerifierKeyParams(SchemaParams prop) {
        return new VerifierKeyParams(
            new VerifierRootQkyChain(Optional.ofNullable(
                prop.getPropertyGroup(VERIFIER_KEY_PARAMS_SINGLE_ROOT_QKY_CHAIN_PATH,
                    VERIFIER_KEY_PARAMS_GROUP, VERIFIER_KEY_CHAIN_GROUP)
            ).orElse(""),
                Optional.ofNullable(
                    prop.getPropertyGroup(VERIFIER_KEY_PARAMS_MULTI_ROOT_QKY_CHAIN_PATH,
                        VERIFIER_KEY_PARAMS_GROUP, VERIFIER_KEY_CHAIN_GROUP)
                ).orElse("")
            ),
            Optional.ofNullable(
                prop.getPropertyGroup(VERIFIER_KEY_PARAMS_KEY_NAME, VERIFIER_KEY_PARAMS_GROUP)
            ).orElse("")
        );
    }

    private LibSpdmParams getLibSpdmParams(SchemaParams prop) {
        return new LibSpdmParams(
            getLibSpdmWrapperLibraryPath(prop),
            getLibSpdmCtExponent(prop),
            getLibSpdmCertificatesEfuseUdsSlotId(prop),
            getLibSpdmMeasurementsRequestSignature(prop)
        );
    }

    private String getLibSpdmWrapperLibraryPath(SchemaParams prop) {
        return Optional.ofNullable(
                prop.getPropertyGroup(LIB_SPDM_WRAPPER_LIBRARY_PATH, LIB_SPDM_PARAMS_GROUP))
            .orElse("");
    }

    int getLibSpdmCtExponent(SchemaParams prop) {
        return Optional.ofNullable(
                prop.getPropertyGroup(LIB_SPDM_CT_EXPONENT, LIB_SPDM_PARAMS_GROUP))
            .filter(StringUtils::isNotBlank)
            .map(this::remove0x)
            .map(s -> toInt(s, LIB_SPDM_CT_EXPONENT))
            .orElse(DEFAULT_LIB_SPDM_CT_EXPONENT);
    }

    int getLibSpdmCertificatesEfuseUdsSlotId(SchemaParams prop) {
        return Optional.ofNullable(
                prop.getPropertyGroup(LIB_SPDM_CERTIFICATES_EFUSE_UDS_SLOT_ID, LIB_SPDM_PARAMS_GROUP))
            .filter(StringUtils::isNotBlank)
            .map(this::remove0x)
            .map(s -> toInt(s, LIB_SPDM_CERTIFICATES_EFUSE_UDS_SLOT_ID))
            .orElse(DEFAULT_LIB_SPDM_CERTIFICATES_EFUSE_UDS_SLOT_ID);
    }

    private boolean getLibSpdmMeasurementsRequestSignature(SchemaParams prop) {
        return Optional.ofNullable(
                prop.getPropertyGroup(LIB_SPDM_MEASUREMENTS_REQUEST_SIGNATURE, LIB_SPDM_PARAMS_GROUP))
            .filter(StringUtils::isNotBlank)
            .map(Boolean::valueOf)
            .orElse(true);
    }

    private DatabaseConfiguration getDatabaseConfiguration(SchemaParams prop) {
        return new DatabaseConfiguration(
            Optional.ofNullable(prop.getPropertyGroup("internal-database", DATABASE_CONFIGURATION_GROUP))
                .map(Boolean::valueOf)
                .orElse(true)
        );
    }

    private SecurityProviderParams getProviderParams(SchemaParams prop) {
        final SecurityProviderParams providerParams = SecurityProviderParamsSetter.setDefaultSecurityProviderParams();

        providerParams.getProvider().setClassName(prop.getPropertyGroup("class-name",
            PROVIDER_PARAMS_GROUP, PROVIDER_GROUP));
        providerParams.getProvider().setName(prop.getPropertyGroup("name",
            PROVIDER_PARAMS_GROUP, PROVIDER_GROUP));
        providerParams.getProvider().setFileBased(Boolean.valueOf(prop.getPropertyGroup("file-based",
            PROVIDER_PARAMS_GROUP, PROVIDER_GROUP)));

        providerParams.getSecurity().setKeyStoreName(prop.getPropertyGroup("key-store-name",
            PROVIDER_PARAMS_GROUP, SECURITY_GROUP));

        providerParams.getSecurity().setPassword(getPass(prop));
        providerParams.getSecurity().setInputStreamParam(prop.getPropertyGroup("input-stream-param",
            PROVIDER_PARAMS_GROUP, SECURITY_GROUP));

        providerParams.getKeyTypes().getEc().setKeyName(prop.getPropertyGroup("key-name",
            PROVIDER_PARAMS_GROUP, KEY_TYPES_GROUP, EC_GROUP));
        providerParams.getKeyTypes().getEc().setCurveSpec384(prop.getPropertyGroup("curve-spec-384",
            PROVIDER_PARAMS_GROUP, KEY_TYPES_GROUP, EC_GROUP));
        providerParams.getKeyTypes().getEc().setCurveSpec256(prop.getPropertyGroup("curve-spec-256",
            PROVIDER_PARAMS_GROUP, KEY_TYPES_GROUP, EC_GROUP));
        providerParams.getKeyTypes().getEc().setSignatureAlgorithm(prop.getPropertyGroup("signature-algorithm",
            PROVIDER_PARAMS_GROUP, KEY_TYPES_GROUP, EC_GROUP));

        return providerParams;
    }

    private boolean getRunGpAttestation(SchemaParams prop) {
        return Optional.ofNullable(prop.getProperty(RUN_GP_ATTESTATION))
            .map(Boolean::valueOf)
            .orElse(false);
    }

    private boolean getTestModeSecrets(SchemaParams prop) {
        return Optional.ofNullable(prop.getProperty(TEST_MODE_SECRETS))
            .map(Boolean::valueOf)
            .orElse(false);
    }

    private int toInt(String value, String param) {
        try {
            return Integer.parseInt(value, 16);
        } catch (NumberFormatException e) {
            throw new VerifierRuntimeException(
                "Provide %s parameter in hexadecimal form or as integer. Example: 0x1A2B or 1A2B or 81."
                    .formatted(param), e);
        }
    }

    private String remove0x(String value) {
        return StringUtils.substringAfter(value, "0x");
    }

    private String getPass(SchemaParams prop) {
        final String password = prop.getPropertyGroup("password", PROVIDER_PARAMS_GROUP, SECURITY_GROUP);
        if (StringUtils.isNotBlank(password)) {
            return password;
        }

        return Optional.ofNullable(System.getenv(VERIFIER_SECURITY_PROVIDER_PASSWORD))
            .orElseThrow(() -> new IllegalArgumentException(
                "Keystore password not found in properties and in environment variables"
                    + " (env:" + VERIFIER_SECURITY_PROVIDER_PASSWORD + ")."));
    }

    private void tryLoadFromExternalSource(Path configPath, Properties prop) throws FileNotFoundException {
        try (InputStream inputStream = Files.newInputStream(configPath)) {
            prop.load(inputStream);
        } catch (IOException exception) {
            throw new FileNotFoundException(String.format("Config file '%s' not found.", configPath));
        }
    }

    private void loadFromClassPath(String filename, Properties prop) throws FileNotFoundException {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(filename)) {
            if (inputStream == null) {
                throwConfigFileNotFound(filename);
            }
            prop.load(inputStream);
        } catch (IOException exception) {
            throwConfigFileNotFound(filename);
        }
    }

    private void throwConfigFileNotFound(String filename) throws FileNotFoundException {
        throw new FileNotFoundException(
            String.format("Config file '%s' not found in the classpath.", filename));
    }
}
