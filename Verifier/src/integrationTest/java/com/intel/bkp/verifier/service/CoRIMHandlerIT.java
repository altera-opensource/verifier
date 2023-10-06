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

package com.intel.bkp.verifier.service;

import ch.qos.logback.classic.Level;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.rim.builder.RimUnsignedBuilder;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.service.CoRimHandler;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.fpgacerts.model.Family;
import com.intel.bkp.test.DiceX509GeneratorUtil;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.verifier.LoggerTestUtil;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import com.intel.bkp.verifier.service.testutils.DesignRimLayer2TestData;
import com.intel.bkp.verifier.service.testutils.DesignRimTestData;
import com.intel.bkp.verifier.service.testutils.DesignRimWithNestedLocatorToItself;
import com.intel.bkp.verifier.service.testutils.FirmwareRimTestData;
import com.intel.bkp.verifier.service.testutils.TestDataBase;
import com.intel.bkp.verifier.service.testutils.TestDataDTO;
import com.intel.bkp.verifier.service.testutils.UnsignedDesignRimTestData;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.FwidHashAlg.FWIDS_HASH_ALG_SHA384;
import static com.intel.bkp.test.FileUtils.getPathFromResources;
import static com.intel.bkp.test.FileUtils.readFromResources;
import static com.intel.bkp.test.rim.ComidBuilderUtils.VENDOR_INTEL;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.utils.PathUtils.buildPath;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class CoRIMHandlerIT {

    @AllArgsConstructor
    @Getter
    private enum TestSuiteParams {
        DESIGN_RIM_WITH_LAYER1(new DesignRimTestData()),
        DESIGN_RIM_WITH_LAYER2(new DesignRimLayer2TestData()),
        FIRMWARE_RIM_WITH_LAYER1(new FirmwareRimTestData()),
        UNSIGNED_DESIGN_RIM_WITH_LAYER1(new UnsignedDesignRimTestData());

        private final TestDataBase data;
    }

    private static final String TEST_FOLDER_INTEGRATION = "integration/";

    private static final String TEST_FOLDER_PRE_CERTS = "certs/dice/common/pre/";

    public static final String BASE_URL_PROD = "https://tsci.intel.com/content/";
    public static final String BASE_URL_PRE = "https://pre1-tsci.intel.com/content/";

    private static final String FILENAME_AGILEX_XRIM = "RIM_Signing_agilex_5WL28Ty-Nta3Si1dR3ralQ7jFHw.xrim";
    private static final String FILENAME_AGILEX_CORIM_CERT = "RIM_Signing_agilex_5WL28Ty-Nta3Si1dR3ralQ7jFHw.cer";

    private static final String FILENAME_AGILEX_CORIM = "signed_valid.rim";

    // Below digest values extracted from CoRIM file parsed with cbor.me website
    private static final String LAYER_0_DIGEST =
        "302E69BA6E3FAC340A57561234E88BFEB2FE373BCE4D4A28C244809CB467C31CA39874CD0D3F346FCA2A9AE874A1D66B";
    private static final String LAYER_1_DIGEST =
        "32883E2526F54EA21FBF99642A8F56E787A0319D1D0E2AF84C36352E9A760EE80EA6C427098D17D26F65723C0C1C66EA";

    private static final String FAMILY_AGILEX = Family.AGILEX.getFamilyName();

    private final TcbInfoMeasurementsAggregator tcbInfoAggregator = new TcbInfoMeasurementsAggregator();

    @TempDir
    Path tempDir;

    @Test
    public void verify_Agilex_CoRim_WithDp_Success() throws Exception {
        // given
        String refMeasurementsAgilexCoRim = readEvidence();
        prepareTcbInfoMeasurementsAggregatorForAgilexCoRIM();
        final DistributionPointConnector dpConnector = mockDpConnector(false);
        final var appContext = spy(AppContext.instance());
        when(appContext.getDpConnector()).thenReturn(dpConnector);

        try (var appContextStaticMock = mockStatic(AppContext.class)) {
            when(AppContext.instance()).thenReturn(appContext);
            final EvidenceVerifier sutWithMockedDpConnector = new EvidenceVerifier();

            // when
            final VerifierExchangeResponse result =
                sutWithMockedDpConnector.verify(tcbInfoAggregator, refMeasurementsAgilexCoRim);

            // then
            assertEquals(VerifierExchangeResponse.OK, result);
        }
    }

    @Test
    public void verify_Agilex_CoRim_WithLocalData_Success() throws Exception {
        // given
        final String unsignedStandalone = buildStandaloneUnsignedRimWithLocalPaths();
        prepareTcbInfoMeasurementsAggregatorForAgilexCoRIM();
        final DistributionPointConnector dpConnector = mockDpConnector(true);
        final var appContext = spy(AppContext.instance());
        when(appContext.getDpConnector()).thenReturn(dpConnector);
        appContext.getLibConfig().setAcceptUnsignedCorim(true);

        try (var appContextStaticMock = mockStatic(AppContext.class)) {
            when(AppContext.instance()).thenReturn(appContext);
            final EvidenceVerifier sutWithMockedDpConnector = new EvidenceVerifier();

            // when
            final VerifierExchangeResponse result =
                sutWithMockedDpConnector.verify(tcbInfoAggregator, unsignedStandalone);

            // then
            assertEquals(VerifierExchangeResponse.OK, result);
        }

        verify(dpConnector, never()).tryGetBytes(BASE_URL_PROD + "IPCS/certs/" + FILENAME_AGILEX_CORIM_CERT);
        verify(dpConnector, never()).tryGetBytes(BASE_URL_PROD + "IPCS/crls/" + FILENAME_AGILEX_XRIM);
    }

    @ParameterizedTest
    @EnumSource(TestSuiteParams.class)
    public void verify_Agilex_CoRim_BatchTests_Success(TestSuiteParams params) throws Exception {
        // given
        final KeyPair keyPair = KeyGenUtils.genEc384();
        final TestDataDTO testData = params.getData().prepare(keyPair);
        tcbInfoAggregator.add(testData.getDeviceData());
        final var dpConnector = mockDesignDistributionPointData(testData.getDpLinks());
        final var rootFingerprint = mockDiceChain(keyPair, dpConnector, testData.getCerLink());

        final var appContext = prepareAppContext(dpConnector, params.getData().isAllowedUnsigned(), rootFingerprint);
        try (var appContextStaticMock = mockStatic(AppContext.class)) {
            when(AppContext.instance()).thenReturn(appContext);
            final EvidenceVerifier sutWithMockedDpConnector = new EvidenceVerifier();

            // when
            final var result = sutWithMockedDpConnector.verify(tcbInfoAggregator, testData.getTestData());

            // then
            assertEquals(VerifierExchangeResponse.OK, result);
        }
    }

    @Test
    public void verify_Agilex_CoRim_NestedLocator_ReachMaximumDepth_Success() throws Exception {
        // given
        final LoggerTestUtil loggerTestUtil = LoggerTestUtil.instance(CoRimHandler.class);
        final var nestedLocatorToItselfPath = tempDir + "/nestedCorim.corim";
        final KeyPair keyPair = KeyGenUtils.genEc384();
        final var data = new DesignRimWithNestedLocatorToItself(nestedLocatorToItselfPath);
        final TestDataDTO testData = data.prepare(keyPair);
        Files.write(Path.of(nestedLocatorToItselfPath), data.getDesignSignedRimData());

        tcbInfoAggregator.add(testData.getDeviceData());
        final var dpConnector = mockDesignDistributionPointData(testData.getDpLinks());
        final var rootFingerprint = mockDiceChain(keyPair, dpConnector, testData.getCerLink());

        final var appContext = prepareAppContext(dpConnector, data.isAllowedUnsigned(), rootFingerprint);

        try (var appContextStaticMock = mockStatic(AppContext.class)) {
            when(AppContext.instance()).thenReturn(appContext);
            final EvidenceVerifier sutWithMockedDpConnector = new EvidenceVerifier();

            // when
            final var result = sutWithMockedDpConnector.verify(tcbInfoAggregator, testData.getTestData());

            // then
            assertEquals(VerifierExchangeResponse.OK, result);
            verifyLogExists(loggerTestUtil, "Stop parsing nested locators at level: 16", Level.DEBUG);
        }
    }

    private static DistributionPointConnector mockDesignDistributionPointData(Map<String, byte[]> inputData) {
        final var dpConnector = mock(DistributionPointConnector.class);
        inputData.forEach((link, data) -> mockTryGetBytes(dpConnector, link, data));
        return dpConnector;
    }

    private static String mockDiceChain(KeyPair keyPair, DistributionPointConnector dpConnector,
                                        String cerLink) throws Exception {
        final var x509GeneratorUtil = new DiceX509GeneratorUtil();
        final List<byte[]> certs = x509GeneratorUtil.generateX509ChainForCaServiceDer(keyPair.getPublic());

        if (cerLink != null) {
            mockTryGetBytes(dpConnector, cerLink, certs.get(0));
            mockTryGetBytes(dpConnector, x509GeneratorUtil.getDpCerUrl(), certs.get(1));

            when(dpConnector.getBytes(x509GeneratorUtil.getDpCrlUrl()))
                .thenReturn(x509GeneratorUtil.generateX509CrlForCaServiceDer());
        }

        return CryptoUtils.generateSha256Fingerprint(certs.get(1));
    }

    private static AppContext prepareAppContext(DistributionPointConnector dpConnector, boolean acceptUnsigned,
                                                String rootFingerprint) {
        final var appContext = spy(AppContext.instance());
        when(appContext.getDpConnector()).thenReturn(dpConnector);
        final String[] trustedRootHash = new String[]{rootFingerprint};
        when(appContext.getDpTrustedRootHashes()).thenReturn(trustedRootHash);
        appContext.getLibConfig().setAcceptUnsignedCorim(acceptUnsigned);
        return appContext;
    }

    private static String buildStandaloneUnsignedRimWithLocalPaths() throws Exception {
        final String originalFile = readEvidence();
        final var unsignedRimData = RimSignedParser.instance().parse(fromHex(originalFile)).getPayload();
        final var replacementPath = "file://" + getPathFromResources(TEST_FOLDER_INTEGRATION, null) + "/";
        final var toReplaceCertsPath = BASE_URL_PROD + "IPCS/certs/";
        final String toReplaceXrimPath = BASE_URL_PROD + "IPCS/crls/";

        final List<LocatorItem> updatedLocators = new ArrayList<>();
        updatedLocators.add(new LocatorItem(LocatorType.CER,
            unsignedRimData.getLocatorLink(LocatorType.CER).orElse("")
                .replace(toReplaceCertsPath, replacementPath)));
        updatedLocators.add(new LocatorItem(LocatorType.XCORIM,
            unsignedRimData.getLocatorLink(LocatorType.XCORIM).orElse("")
                .replace(toReplaceXrimPath, replacementPath)));
        unsignedRimData.setLocators(updatedLocators);
        return toHex(RimUnsignedBuilder.instance().standalone().build(unsignedRimData));
    }

    private static DistributionPointConnector mockDpConnector(boolean withLocalData) {
        final var dpConnector = mock(DistributionPointConnector.class);
        if (!withLocalData) {
            mockTryGetBytes(dpConnector, buildPath(BASE_URL_PROD, "IPCS/certs/"), FILENAME_AGILEX_CORIM_CERT,
                CoRIMHandlerIT::readCertificate);
            mockTryGetBytes(dpConnector, buildPath(BASE_URL_PROD, "IPCS/crls/"), FILENAME_AGILEX_XRIM,
                CoRIMHandlerIT::readCertificate);
        }
        mockTryGetBytes(dpConnector, buildPath(BASE_URL_PRE, "IPCS/certs/"), "IPCS_agilex.cer",
            CoRIMHandlerIT::readFileFromPre);
        mockTryGetBytes(dpConnector, buildPath(BASE_URL_PRE, "DICE/certs/"), "DICE_RootCA.cer",
            CoRIMHandlerIT::readFileFromPre);
        mockGetBytes(dpConnector, buildPath(BASE_URL_PRE, "IPCS/crls/"), "IPCS_agilex.crl");
        mockGetBytes(dpConnector, buildPath(BASE_URL_PRE, "DICE/crls/"), "DICE.crl");
        return dpConnector;
    }

    @SneakyThrows
    private static byte[] readCertificate(String filename) {
        return readFromResources(TEST_FOLDER_INTEGRATION, filename);
    }

    @SneakyThrows
    private static byte[] readFileFromPre(String filename) {
        return readFromResources(TEST_FOLDER_PRE_CERTS, filename);
    }

    private static void mockTryGetBytes(DistributionPointConnector dpConnector, String url, String fileName,
                                        Function<String, byte[]> readBytes) {
        when(dpConnector.tryGetBytes(buildPath(url, fileName))).thenReturn(Optional.of(readBytes.apply(fileName)));
    }

    private static void mockTryGetBytes(DistributionPointConnector dpConnector, String path, byte[] data) {
        when(dpConnector.tryGetBytes(path)).thenReturn(Optional.of(data));
    }

    private static void mockGetBytes(DistributionPointConnector dpConnector, String url, String fileName) {
        when(dpConnector.getBytes(buildPath(url, fileName))).thenReturn(readFileFromPre(fileName));
    }

    private void prepareTcbInfoMeasurementsAggregatorForAgilexCoRIM() {
        final String hashAlg = FWIDS_HASH_ALG_SHA384.getOid();
        final List<TcbInfoMeasurement> measurements = List.of(
            new TcbInfoMeasurement(
                TcbInfoKey.builder().vendor(VENDOR_INTEL).model(FAMILY_AGILEX).layer(0).index(0).build(),
                TcbInfoValue.builder().svn(Optional.of(0)).fwid(
                    Optional.of(new FwIdField(hashAlg, LAYER_0_DIGEST))).build()
            ),
            new TcbInfoMeasurement(
                TcbInfoKey.builder().vendor(VENDOR_INTEL).model(FAMILY_AGILEX).layer(1).index(0).build(),
                TcbInfoValue.builder().svn(Optional.of(0)).fwid(
                    Optional.of(new FwIdField(hashAlg, LAYER_1_DIGEST))).build()
            )
        );
        tcbInfoAggregator.add(measurements);
    }

    private static String readEvidence() throws Exception {
        return toHex(readFromResources(TEST_FOLDER_INTEGRATION, CoRIMHandlerIT.FILENAME_AGILEX_CORIM));
    }

    private void verifyLogExists(LoggerTestUtil loggerTestUtil, String log, Level level) {
        assertTrue(loggerTestUtil.contains(log, level));
    }
}
