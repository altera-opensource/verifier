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

package com.intel.bkp.fpgacerts.cbor.service;

import com.intel.bkp.fpgacerts.cbor.CborBroker;
import com.intel.bkp.fpgacerts.cbor.CborConverter;
import com.intel.bkp.fpgacerts.cbor.CborObjectParser;
import com.intel.bkp.fpgacerts.cbor.CborParserBase;
import com.intel.bkp.fpgacerts.cbor.LocatorTreeNodeMockedFields;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.LocatorsTreeNode;
import com.intel.bkp.fpgacerts.cbor.exception.RimVerificationException;
import com.intel.bkp.fpgacerts.cbor.rim.Comid;
import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.comid.Claims;
import com.intel.bkp.fpgacerts.cbor.rim.comid.ReferenceTriple;
import com.intel.bkp.fpgacerts.cbor.rim.comid.mapping.ReferenceTripleToTcbInfoMeasurementMapper;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.signer.CborSignatureVerifier;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.utils.ProfileValidator;
import com.intel.bkp.fpgacerts.cbor.utils.SignatureTimeValidator;
import com.intel.bkp.fpgacerts.cbor.xrim.XrimService;
import com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementHolder;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.fpgacerts.url.FetchDataSchemeBroker;
import com.intel.bkp.test.rim.OneKeyGenerator;
import com.intel.bkp.test.rim.RimGenerator;
import com.upokecenter.cbor.CBORObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.intel.bkp.fpgacerts.cbor.service.CoRimHandler.MAX_NESTED_LOCATORS_DEPTH;
import static com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId.ECDSA_384;
import static java.util.Collections.emptyList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.matches;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CoRimHandlerTest {

    private static final String CERTIFICATE_PATH_REGEX = "http://localhost:9090/content/IPCS/rims/agilex_L1_.*\\.corim";

    private static CborKeyPair signingKey;

    @Mock
    private TcbInfoMeasurement tcbInfoMeasurement;

    @Mock
    private DistributionPointConnector distributionPointConnector;

    @Mock
    private ReferenceTripleToTcbInfoMeasurementMapper measurementMapper;

    @Mock
    private RimSigningChainService chainService;

    @Mock
    private CborSignatureVerifier cborSignatureVerifier;

    @Mock
    private XrimService xrimService;

    @Mock
    private CborConverter cborConverter;

    @Mock
    private RimSignedParser rimSignedParser;

    @Mock
    private CborObjectParser cborObjectParser;

    @Mock
    private CBORObject cborA, cborB, cborC, cborD, cborE, cborF, cborG, cborD1, cborD2, cborD3;

    private CoRimHandler sut;

    private static CBORObject generateSignedRim(boolean designRim) {
        final byte[] signed = RimGenerator.instance()
            .design(designRim)
            .privateKey(signingKey.getPrivateKey())
            .publicKey(signingKey.getPublicKey())
            .generate();
        return CborObjectParser.instance().parse(signed);
    }

    private static byte[] generateSignedRim() {
        return RimGenerator.instance()
            .privateKey(signingKey.getPrivateKey())
            .publicKey(signingKey.getPublicKey())
            .generate();
    }

    private static CBORObject generateUnsignedRim() {
        final byte[] signed = RimGenerator.instance()
            .signed(false)
            .publicKey(signingKey.getPublicKey())
            .generate();
        return CborObjectParser.instance().parse(signed);
    }

    @BeforeEach
    void setUp() throws Exception {
        sut = new CoRimHandler(measurementMapper, chainService, cborSignatureVerifier, xrimService, false,
            distributionPointConnector);
        signingKey = OneKeyGenerator.generate(ECDSA_384);
    }

    @Test
    void getFormatName_Success() {
        //when-then
        assertEquals("CBOR CoRIM", sut.getFormatName());
    }

    @Test
    void getMeasurements_Success() {
        // given
        final var cbor = generateSignedRim(false);
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), cbor)).thenReturn(true);
        when(measurementMapper.map(any())).thenReturn(tcbInfoMeasurement).thenReturn(tcbInfoMeasurement)
            .thenReturn(tcbInfoMeasurement);
        mockTcbInfoMeasurement();

        // when
        final var result = sut.getMeasurements(cbor);

        // then
        assertIterableEquals(List.of(tcbInfoMeasurement, tcbInfoMeasurement), result.getReferenceMeasurements());
        assertIterableEquals(List.of(tcbInfoMeasurement), result.getEndorsedMeasurements());
    }

    @Test
    void getMeasurements_WithDesignRim_Success() {
        // given
        final var designRimCbor = generateSignedRim(true);
        final var signedRimCbor = generateSignedRim();
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), designRimCbor)).thenReturn(true);
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), CborObjectParser.instance().parse(signedRimCbor)))
            .thenReturn(true);
        when(measurementMapper.map(any())).thenReturn(tcbInfoMeasurement).thenReturn(tcbInfoMeasurement);
        mockTcbInfoMeasurement();
        when(distributionPointConnector.tryGetBytes(matches(CERTIFICATE_PATH_REGEX)))
            .thenReturn(Optional.of(signedRimCbor));

        // when
        final var result = toOneList(sut.getMeasurements(designRimCbor));

        // then
        assertEquals(9, result.size());
    }

    @Test
    void getMeasurements_WithDesignRim_WithMissingRimOnDp_ThrowsException() {
        // given
        final var designRimCbor = generateSignedRim(true);
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), designRimCbor)).thenReturn(true);
        when(distributionPointConnector.tryGetBytes(matches(CERTIFICATE_PATH_REGEX)))
            .thenReturn(Optional.empty());

        // when-then
        final var ex = assertThrows(RimVerificationException.class, () -> sut.getMeasurements(designRimCbor));

        // then
        assertTrue(ex.getMessage().contains("CoRIM verification failed: failed to download data from path:"));
    }

    @Test
    void getMeasurements_WithUnsignedRim_IsUnsignedSupportedTrue_Success() {
        // given
        final var cbor = generateUnsignedRim();
        when(measurementMapper.map(any())).thenReturn(tcbInfoMeasurement).thenReturn(tcbInfoMeasurement)
            .thenReturn(tcbInfoMeasurement);
        mockTcbInfoMeasurement();

        // when
        final var sutWithUnsignedSupport =
            sut = new CoRimHandler(measurementMapper, chainService, cborSignatureVerifier, xrimService, true,
                distributionPointConnector);
        final var result = sutWithUnsignedSupport.getMeasurements(cbor);

        // then
        verify(cborSignatureVerifier, never()).verify(any(), (CBORObject) any());
        assertIterableEquals(List.of(tcbInfoMeasurement, tcbInfoMeasurement), result.getReferenceMeasurements());
        assertIterableEquals(List.of(tcbInfoMeasurement), result.getEndorsedMeasurements());
    }

    @Test
    void getMeasurements_WithUnsignedRim_IsUnsignedSupportedFalse_Throws() {
        // given
        final var cbor = generateUnsignedRim();

        // when-then
        final var ex = assertThrows(RimVerificationException.class, () -> sut.getMeasurements(cbor));

        // then
        verify(cborSignatureVerifier, never()).verify(any(), (CBORObject) any());
        assertEquals("CoRIM verification failed: CoRIM not signed. Signature cannot be verified.", ex.getMessage());
    }

    @Test
    void getMeasurements_WithSignatureVerificationFailure_Throws() {
        // given
        final var cbor = generateSignedRim(false);
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());
        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), cbor)).thenReturn(false);

        // when-then
        final var ex = assertThrows(RimVerificationException.class, () -> sut.getMeasurements(cbor));

        // then
        assertEquals("CoRIM verification failed: invalid signature.", ex.getMessage());
    }

    @Test
    void getMeasurements_WithExpiredSignatureFailure_Throws() throws Exception {
        // given
        final CborKeyPair pair = OneKeyGenerator.generate(ECDSA_384);
        final byte[] signed = RimGenerator
            .instance()
            .privateKey(pair.getPrivateKey())
            .publicKey(pair.getPublicKey())
            .expired(true)
            .generate();

        final var cbor = CborObjectParser.instance().parse(signed);

        // when-then
        final var ex = assertThrows(RimVerificationException.class, () -> sut.getMeasurements(cbor));

        // then
        assertTrue(ex.getMessage().contains("CoRIM verification failed: signature expired at:"));
    }

    @Test
    void getMeasurements_WithLocatorsTree_Success() {
        // given
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());

        try (var cborBrokerMockedStatic = mockStatic(CborBroker.class);
             var signatureTimeValidatorMockedStatic = mockStatic(SignatureTimeValidator.class);
             var profileValidatorMockedStatic = mockStatic(ProfileValidator.class);
             var fetchDataSchemeBrokerMockedStatic = mockStatic(FetchDataSchemeBroker.class);
             var cborObjectParserMockedStatic = mockStatic(CborObjectParser.class)) {
            final List<LocatorsTreeNode> nodeList = mockRimWithLocatorsTree();

            nodeList.stream().skip(1).forEach(node -> mockCborObjectParser(node.getObject(), node.getLink()));

            nodeList.forEach(node -> mockSingleNode(node.getObject(), node.getMocks().measurement(),
                node.getMocks().triple(), node.getMocks().comid(), node.getMocks().claims(),
                node.getMocks().rimUnsigned(), node.getMocks().rimSigned(), node.getChildren()));

            // when
            final var result = sut.getMeasurements(cborA);

            // then
            final var expected = nodeList.stream().map(node -> node.getMocks().measurement()).toList();
            assertTrue(expected.containsAll(result.getReferenceMeasurements()));
            assertIterableEquals(emptyList(), result.getEndorsedMeasurements());
        }
    }

    @Test
    void getMeasurements_WithMaxDepth_Success() {
        // given
        when(chainService.verifyRimSigningChainAndGetRimSigningKey(any(String.class)))
            .thenReturn(signingKey.getPublicKey());

        try (var cborBrokerMockedStatic = mockStatic(CborBroker.class);
             var signatureTimeValidatorMockedStatic = mockStatic(SignatureTimeValidator.class);
             var profileValidatorMockedStatic = mockStatic(ProfileValidator.class);
             var fetchDataSchemeBrokerMockedStatic = mockStatic(FetchDataSchemeBroker.class);
             var cborObjectParserMockedStatic = mockStatic(CborObjectParser.class)) {

            final var lastNode = new LocatorsTreeNode(cborB, generateInternalMocks(), "B");
            final var nodeList = mockRimWithMaxDepth(lastNode);
            mockCborObjectParser(lastNode.getObject(), lastNode.getLink());

            nodeList.stream().skip(1).forEach(node -> mockCborObjectParser(node.getObject(), node.getLink()));

            nodeList.forEach(node -> mockSingleNode(node.getObject(), node.getMocks().measurement(),
                node.getMocks().triple(), node.getMocks().comid(), node.getMocks().claims(),
                node.getMocks().rimUnsigned(), node.getMocks().rimSigned(), node.getChildren()));

            // when
            final var result = sut.getMeasurements(cborA);

            // then
            final var expected = nodeList.stream().map(node -> node.getMocks().measurement()).toList();
            assertTrue(expected.containsAll(result.getReferenceMeasurements()));
            assertFalse(result.getReferenceMeasurements().contains(lastNode.getMocks().measurement()));
            assertIterableEquals(emptyList(), result.getEndorsedMeasurements());
        }
    }

    private void mockTcbInfoMeasurement() {
        when(tcbInfoMeasurement.getKey()).thenReturn(TcbInfoKey.builder().build());
        when(tcbInfoMeasurement.getValue()).thenReturn(TcbInfoValue.builder().build());
    }

    private List<TcbInfoMeasurement> toOneList(MeasurementHolder holder) {
        return Stream.of(holder.getReferenceMeasurements(), holder.getEndorsedMeasurements())
            .flatMap(List::stream)
            .collect(Collectors.toList());
    }

    /*  Structure of locators:

                           A
                         /   \
                        B      C
                       / \     / \
                     D    E   F   G
                  /  |  \
                 D1  D2  D3
    */
    private List<LocatorsTreeNode> mockRimWithLocatorsTree() {
        LocatorsTreeNode nodeA =
            new LocatorsTreeNode(cborA, generateInternalMocks(), "A");

        LocatorsTreeNode nodeC = nodeA.addChild(cborC, generateInternalMocks(), "C");

        LocatorsTreeNode nodeF = nodeC.addChild(cborF, generateInternalMocks(), "F");
        LocatorsTreeNode nodeG = nodeC.addChild(cborG, generateInternalMocks(), "G");

        LocatorsTreeNode nodeB = nodeA.addChild(cborB, generateInternalMocks(), "B");
        LocatorsTreeNode nodeE = nodeB.addChild(cborE, generateInternalMocks(), "E");
        LocatorsTreeNode nodeD = nodeB.addChild(cborD, generateInternalMocks(), "D");

        LocatorsTreeNode nodeD1 = nodeD.addChild(cborD1, generateInternalMocks(), "D1");
        LocatorsTreeNode nodeD2 = nodeD.addChild(cborD2, generateInternalMocks(), "D2");
        LocatorsTreeNode nodeD3 = nodeD.addChild(cborD3, generateInternalMocks(), "D3");

        return Arrays.asList(nodeA, nodeB, nodeC, nodeD, nodeE, nodeF, nodeG, nodeD1, nodeD2, nodeD3);
    }

    /*  Structure of locators:

                       A
                       |
                       1
                       |
                      ...
                       |
                       15
                       |
                       B
    */
    private List<LocatorsTreeNode> mockRimWithMaxDepth(LocatorsTreeNode lastNode) {
        final var rootNode = new LocatorsTreeNode(cborA, generateInternalMocks() , "A");

        final var locatorsTree = new ArrayList<LocatorsTreeNode>();
        locatorsTree.add(rootNode);
        LocatorsTreeNode currentNode = rootNode;

        for (Integer i = 0; i < MAX_NESTED_LOCATORS_DEPTH; i++) {
            currentNode = currentNode.addChild(mock(CBORObject.class), generateInternalMocks(), i.toString());
            locatorsTree.add(currentNode);
        }
        currentNode.addChild(lastNode);
        return locatorsTree;
    }

    private void mockSingleNode(CBORObject cbor, TcbInfoMeasurement tim, ReferenceTriple referenceTriple, Comid comid,
                                Claims claims, RimUnsigned rimUnsigned, RimSigned rimSigned,
                                List<LocatorsTreeNode> children) {
        when(CborBroker.detectCborType(cbor)).thenReturn(cborConverter);
        final List<Comid> listOfComids = new ArrayList<>();
        final List<ReferenceTriple> referenceTriples = new ArrayList<>();
        when(cborConverter.getParser()).thenReturn((CborParserBase) rimSignedParser);

        when(rimSignedParser.parse(cbor)).thenReturn(rimSigned);
        when(rimSigned.getPayload()).thenReturn(rimUnsigned);

        when(rimUnsigned.getLocatorLink(LocatorType.CER)).thenReturn(Optional.of(""));
        listOfComids.add(comid);
        when(rimUnsigned.getComIds()).thenReturn(listOfComids);
        when(comid.getClaims()).thenReturn(claims);

        referenceTriples.add(referenceTriple);
        when(claims.getReferenceTriples()).thenReturn(referenceTriples);
        when(measurementMapper.map(referenceTriple)).thenReturn(tim);

        final var locatorList = children.stream().map(
            LocatorsTreeNode::getLink).toList();
        when(rimUnsigned.getLocatorLinks(LocatorType.CORIM)).thenReturn(locatorList);

        when(cborSignatureVerifier.verify(signingKey.getPublicKey(), cbor)).thenReturn(true);
        when(tim.getKey()).thenReturn(TcbInfoKey.builder().build());
        when(tim.getValue()).thenReturn(TcbInfoValue.builder().build());
    }

    private void mockCborObjectParser(CBORObject cbor, String link) {
        when(CborObjectParser.instance()).thenReturn(cborObjectParser);
        when(cborObjectParser.parse(link.getBytes())).thenReturn(cbor);
        when(FetchDataSchemeBroker.fetchData(link, distributionPointConnector))
            .thenReturn(Optional.of(link.getBytes()));
    }

    private LocatorTreeNodeMockedFields generateInternalMocks() {
        return new LocatorTreeNodeMockedFields(mock(TcbInfoMeasurement.class),
            mock(ReferenceTriple.class), mock(Comid.class), mock(Claims.class), mock(RimSigned.class),
            mock(RimUnsigned.class));
    }
}
