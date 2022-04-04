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

import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.model.LibConfig;
import com.intel.bkp.verifier.model.TransportLayerType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LibConfigParserTest {

    private static final String CONFIG_RESOURCES_DIR = "config/";
    private static final String CONFIG_WITH_ALL_SET = "config_with_all_set.properties";
    private static final String CONFIG_EMPTY_OPTIONALS = "config_with_empty_optional.properties";
    private static final String CONFIG_WITHOUT_OPTIONALS = "config_without_optional.properties";
    private static final String CONFIG_WRONG = "config_wrong.properties";
    private static final String CONFIG_MISSING = "config_wrong_missing.properties";
    private static final String CONFIG_IN_CLASSPATH = "config_in_classpath.properties";
    private static Path configDirectory;

    private final LibConfigParser sut = new LibConfigParser();

    @BeforeAll
    static void init() throws URISyntaxException {
        configDirectory = getExternalDirectoryPathForConfig(CONFIG_RESOURCES_DIR + CONFIG_WITH_ALL_SET);
    }

    @Test
    void parseFile_WithAllSet_Success() throws Exception {
        // given
        LibConfigParser spy = Mockito.spy(sut);
        when(spy.getDirectory()).thenReturn(configDirectory);

        // when
        LibConfig config = spy.parseConfigFile(CONFIG_WITH_ALL_SET);

        // then
        Assertions.assertNotNull(config);
        Assertions.assertEquals(TransportLayerType.HPS, config.getTransportLayerType());
        Assertions.assertFalse(config.getAttestationCertificateFlow().isOnlyEfuseUds());
        Assertions.assertTrue(config.getDatabaseConfiguration().isInternalDatabase());

        Assertions.assertEquals("path/to/single-rooted-chain",
            config.getVerifierKeyParams().getVerifierRootQkyChain().getSingleChainPath());
        Assertions.assertEquals("some-key-name", config.getVerifierKeyParams().getKeyName());

        var distributionPoint = config.getDistributionPoint();
        Assertions.assertEquals("https://tsci.intel.com/content/IPCS/certs/", distributionPoint.getPathCer());
        Assertions.assertEquals("99B174476980A65FC581F499F60295B9DACA5E7DBAEEC25ECF3988049EC9ED5F",
            distributionPoint.getTrustedRootHash().getS10());
        Assertions.assertEquals("35E08599DD52CB7533764DEE65C915BBAFD0E35E6252BCCD77F3A694390F618B",
            distributionPoint.getTrustedRootHash().getDice());
        Assertions.assertEquals("proxy.intel.com", distributionPoint.getProxy().getHost());
        Assertions.assertEquals(912, distributionPoint.getProxy().getPort());

        var securityProviderParams = config.getProviderParams();
        Assertions.assertNotNull(securityProviderParams);

        var provider = securityProviderParams.getProvider();
        Assertions.assertEquals("BC", provider.getName());
        Assertions.assertTrue(provider.getFileBased());
        Assertions.assertEquals("org.bouncycastle.jce.provider.BouncyCastleProvider", provider.getClassName());

        var security = securityProviderParams.getSecurity();
        Assertions.assertEquals("uber", security.getKeyStoreName());
        Assertions.assertEquals("default-password", security.getPassword());
        Assertions.assertEquals("/tmp/bc-keystore-verifier.jks", security.getInputStreamParam());

        var keyTypes = securityProviderParams.getKeyTypes();
        Assertions.assertNotNull(keyTypes);

        var ec = keyTypes.getEc();
        Assertions.assertEquals("EC", ec.getKeyName());
        Assertions.assertEquals("secp384r1", ec.getCurveSpec384());
        Assertions.assertEquals("secp256r1", ec.getCurveSpec256());
        Assertions.assertEquals("SHA384withECDSA", ec.getSignatureAlgorithm());
    }

    @Test
    void parseFile_WithEmptyOptionals_Success() throws Exception {
        // given
        LibConfigParser spy = Mockito.spy(sut);
        when(spy.getDirectory()).thenReturn(configDirectory);

        // when
        LibConfig config = spy.parseConfigFile(CONFIG_EMPTY_OPTIONALS);

        // then
        var distributionPoint = config.getDistributionPoint();
        Assertions.assertEquals("", distributionPoint.getTrustedRootHash().getS10());
        Assertions.assertEquals("", distributionPoint.getProxy().getHost());
        Assertions.assertNull(distributionPoint.getProxy().getPort());
    }

    @Test
    void parseFile_WithoutOptionals_Success() throws Exception {
        // given
        LibConfigParser spy = Mockito.spy(sut);
        when(spy.getDirectory()).thenReturn(configDirectory);

        // when
        LibConfig config = spy.parseConfigFile(CONFIG_WITHOUT_OPTIONALS);

        // then
        var distributionPoint = config.getDistributionPoint();
        Assertions.assertNull(distributionPoint.getProxy().getHost());
        Assertions.assertNull(distributionPoint.getProxy().getPort());
    }

    @Test
    void parseFile_NotValidConfiguration_ThrowsException() throws Exception {
        // given
        LibConfigParser spy = Mockito.spy(sut);
        when(spy.getDirectory()).thenReturn(configDirectory);

        // when - then
        Assertions.assertThrows(IllegalArgumentException.class, () ->
            spy.parseConfigFile(CONFIG_WRONG));
    }

    @Test
    void parseFile_MissingExternalFile_FindsInClassPath() {
        // when
        final LibConfig config = sut.parseConfigFile(CONFIG_IN_CLASSPATH);

        // then
        Assertions.assertNotNull(config);
        Assertions.assertEquals(TransportLayerType.HPS, config.getTransportLayerType());
    }

    @Test
    void parseFile_MissingExternalFileAndClassPath_Throws() {
        // when - then
        Assertions.assertThrows(InternalLibraryException.class, () ->
            sut.parseConfigFile(CONFIG_MISSING));
    }

    private static Path getExternalDirectoryPathForConfig(String configName) throws URISyntaxException {
        final URL resource = LibConfigParserTest.class.getClassLoader().getResource(configName);
        assert resource != null;
        return Paths.get(resource.toURI()).getParent();
    }
}
