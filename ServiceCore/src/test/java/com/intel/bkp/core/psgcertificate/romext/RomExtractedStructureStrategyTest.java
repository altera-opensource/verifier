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

package com.intel.bkp.core.psgcertificate.romext;

import com.intel.bkp.core.RomExtensionAuthGeneratorUtil;
import com.intel.bkp.core.TestUtil;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.psgcertificate.PsgCancellableBlock0EntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntryBuilder;
import com.intel.bkp.core.psgcertificate.exceptions.RomExtensionStrategyException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCancellableBlock0Entry;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.crypto.constants.CryptoConstants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.core.TestUtil.genEcKeys;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RomExtractedStructureStrategyTest {

    private static final EndiannessActor ACTOR = EndiannessActor.SERVICE;
    private static final byte[] DUMMY_DATA = new byte[]{1, 2, 3, 4};

    @Mock
    private RomExtensionSignatureBuilder signatureBuilder;

    private final List<PsgCertificateEntryBuilder> builders = new ArrayList<>();

    @Test
    void parse_Root_Success() {
        // given
        final byte[] content = getContentCertificate(PsgCertificateType.ROOT);

        // when-then
        Assertions.assertDoesNotThrow(
            () -> RomExtractedStructureStrategy.ROOT.parse(signatureBuilder, ACTOR, content)
        );

        //then
        Mockito.verify(signatureBuilder).setPsgCertRootBuilder(any(PsgCertificateRootEntryBuilder.class));
    }

    @Test
    void parse_Root_ThrowsException() {
        // when-then
        Assertions.assertThrows(RomExtensionStrategyException.class,
            () -> RomExtractedStructureStrategy.ROOT.parse(signatureBuilder, ACTOR, DUMMY_DATA)
        );

        //then
        Mockito.verifyNoInteractions(signatureBuilder);
    }

    @Test
    void parse_Leaf_Success() {
        // given
        when(signatureBuilder.getPsgCertEntryBuilders()).thenReturn(builders);
        final byte[] content = getContentCertificate(PsgCertificateType.LEAF);

        // when-then
        Assertions.assertDoesNotThrow(
            () -> RomExtractedStructureStrategy.LEAF.parse(signatureBuilder, ACTOR, content)
        );

        //then
        Assertions.assertEquals(1, builders.size());
    }

    @Test
    void parse_Leaf_ThrowsException() {
        // given
        when(signatureBuilder.getPsgCertEntryBuilders()).thenReturn(builders);

        // when-then
        Assertions.assertThrows(RomExtensionStrategyException.class,
            () -> RomExtractedStructureStrategy.LEAF.parse(signatureBuilder, ACTOR, DUMMY_DATA)
        );

        //then
        Assertions.assertEquals(0, builders.size());
    }

    @Test
    void parse_Block0_Success() {
        // given
        final byte[] content = prepareBlock0Entry().array();

        // when-then
        Assertions.assertDoesNotThrow(
            () -> RomExtractedStructureStrategy.BLOCK0.parse(signatureBuilder, ACTOR, content)
        );

        //then
        Mockito.verify(signatureBuilder)
            .setPsgCancellableBlock0EntryBuilder(any(PsgCancellableBlock0EntryBuilder.class));
    }

    @Test
    void parse_Block0_ThrowsException() {
        // when-then
        Assertions.assertThrows(RomExtensionStrategyException.class,
            () -> RomExtractedStructureStrategy.BLOCK0.parse(signatureBuilder, ACTOR, DUMMY_DATA)
        );

        //then
        Mockito.verifyNoInteractions(signatureBuilder);
    }

    private static byte[] getContentCertificate(PsgCertificateType type) {
        return new RomExtensionAuthGeneratorUtil()
            .getMultiCertChain()
            .stream()
            .filter(wrapper -> wrapper.getType() == type)
            .findAny()
            .map(CertificateEntryWrapper::getContent)
            .orElseThrow(RuntimeException::new);
    }

    private PsgCancellableBlock0Entry prepareBlock0Entry() {
        KeyPair keyPair = genEcKeys(null);
        byte[] dataToSign = new byte[1];
        assert keyPair != null;
        final byte[] signedData = TestUtil.signEcData(dataToSign, keyPair.getPrivate(),
            CryptoConstants.SHA384_WITH_ECDSA);
        return new PsgCancellableBlock0EntryBuilder()
            .signature(signedData, PsgSignatureCurveType.SECP384R1)
            .withActor(ACTOR)
            .build();
    }
}
