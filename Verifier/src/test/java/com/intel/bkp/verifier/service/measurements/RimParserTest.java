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

package com.intel.bkp.verifier.service.measurements;

import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import com.intel.bkp.verifier.Utils;
import com.intel.bkp.verifier.model.evidence.BaseEvidenceBlock;
import com.intel.bkp.verifier.model.evidence.Rim;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoConstants.FWIDS_HASH_ALG;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoConstants.VENDOR;

@ExtendWith(MockitoExtension.class)
class RimParserTest {

    private static final String TEST_FOLDER = "evidence/";
    private static final String FILENAME_STRATIX = "stratix10.rim";
    private static final String FILENAME_AGILEX = "agilex.rim";

    private static String refMeasurementsStratix;
    private static String refMeasurementsAgilex;

    @InjectMocks
    private RimParser sut;

    @BeforeAll
    static void init() throws Exception {
        refMeasurementsStratix = readEvidence(FILENAME_STRATIX);
        refMeasurementsAgilex = readEvidence(FILENAME_AGILEX);
    }

    private static String readEvidence(String filename) throws Exception {
        return new String(Utils.readFromResources(TEST_FOLDER, filename));
    }

    @Test
    void parse_Stratix10() {
        // when
        final Rim result = sut.parse(refMeasurementsStratix);

        // then
        final List<BaseEvidenceBlock> blocks = result.getRimRecords().getRecords();
        Assertions.assertNotNull(blocks);
        Assertions.assertEquals(5, blocks.size());

        assertSectionLayer1(blocks);
        assertIoSection(blocks);
        assertCoreSection(blocks);
        assertPrSection(blocks);
        assertDeviceStateSection(blocks);
    }

    @Test
    void parse_Agilex() {
        // when
        final Rim result = sut.parse(refMeasurementsAgilex);

        // then
        final List<BaseEvidenceBlock> blocks = result.getRimRecords().getRecords();
        Assertions.assertNotNull(blocks);
        Assertions.assertEquals(8, blocks.size());

        assertSectionLayer1Agilex(blocks);
        assertIoSection(blocks);
        assertCoreSection(blocks);
        assertPrSection(blocks);
        assertDeviceStateSectionAgilex(blocks);
        assertSecondPrSectionAgilex(blocks);
        assertUntypedSectionLayer0Agilex(blocks);
        assertUntypedSectionLayer2Agilex(blocks);
    }

    private void assertSectionLayer1(List<BaseEvidenceBlock> blocks) {
        assertSectionLayer1Common(blocks, "Stratix10", "153C3348F49C3FC35166B29E1D68106"
            + "39097ED74D2F44B46C148D59F8E0C7FDA9B164CAE8904003A24BD0BE285350117");
    }

    private void assertSectionLayer1Agilex(List<BaseEvidenceBlock> blocks) {
        assertSectionLayer1Common(blocks, "Agilex", "0000000000000000000000000000000000"
            + "00000000000000000000000000000000000000000000000000000000000000");
    }

    private void assertSectionLayer1Common(List<BaseEvidenceBlock> blocks, String modelName, String expectedHash) {
        final BaseEvidenceBlock block = blocks.get(0);
        Assertions.assertEquals(VENDOR, block.getVendor());
        Assertions.assertEquals(modelName, block.getModel());
        Assertions.assertEquals("1", block.getLayer());
        Assertions.assertEquals(1, block.getFwids().size());

        final FwIdField fwIds = block.getFwids().get(0);
        Assertions.assertEquals(FWIDS_HASH_ALG, fwIds.getHashAlg());
        Assertions.assertEquals(expectedHash, fwIds.getDigest());
    }

    private void assertIoSection(List<BaseEvidenceBlock> blocks) {
        final BaseEvidenceBlock block = blocks.get(1);
        Assertions.assertEquals(VENDOR, block.getVendor());
        Assertions.assertEquals("2.16.840.1.113741.1.15.4.2", block.getType());
        Assertions.assertEquals("2", block.getLayer());
        Assertions.assertEquals(1, block.getFwids().size());

        final FwIdField fwIds = block.getFwids().get(0);
        Assertions.assertEquals(FWIDS_HASH_ALG, fwIds.getHashAlg());
        Assertions.assertEquals("664AAD52B52B717A2597CBFE0D1BF43FD5860DB48EFEDA21C9C2"
            + "D892828BA70BE61162A273A8A7156337CD8343CA24FE", fwIds.getDigest());
    }

    private void assertCoreSection(List<BaseEvidenceBlock> blocks) {
        final BaseEvidenceBlock block = blocks.get(2);
        Assertions.assertEquals(VENDOR, block.getVendor());
        Assertions.assertEquals("2.16.840.1.113741.1.15.4.3", block.getType());
        Assertions.assertEquals("2", block.getLayer());
        Assertions.assertEquals(1, block.getFwids().size());

        final FwIdField fwIds = block.getFwids().get(0);
        Assertions.assertEquals(FWIDS_HASH_ALG, fwIds.getHashAlg());
        Assertions.assertEquals("5D04018373C58AB309644118599094F7A5CF759F9C2F14759B24"
            + "35F3387F4DAF9B05DBF6BC25D215F16BC81FB93F9F2B", fwIds.getDigest());
    }

    private void assertPrSection(List<BaseEvidenceBlock> blocks) {
        final BaseEvidenceBlock block = blocks.get(3);
        Assertions.assertEquals(VENDOR, block.getVendor());
        Assertions.assertEquals("2.16.840.1.113741.1.15.4.6", block.getType());
        Assertions.assertEquals("2", block.getLayer());
        Assertions.assertEquals(16777216, block.getIndex());
        Assertions.assertEquals(1, block.getFwids().size());

        final FwIdField fwIds = block.getFwids().get(0);
        Assertions.assertEquals(FWIDS_HASH_ALG, fwIds.getHashAlg());
        Assertions.assertEquals("CBF9E12CDF8ED22F9752574E440A5964458AAEFFDE7533EF1636"
            + "8DE4551F90282AC2A890BE1C42796B3385686AC3CB81", fwIds.getDigest());
    }

    private void assertDeviceStateSection(List<BaseEvidenceBlock> blocks) {
        final BaseEvidenceBlock block = blocks.get(4);
        Assertions.assertEquals(VENDOR, block.getVendor());
        Assertions.assertEquals("2.16.840.1.113741.1.15.4.1", block.getType());
        Assertions.assertEquals("2", block.getLayer());
        Assertions.assertEquals("0002000002020200", block.getVendorInfo());
        Assertions.assertEquals("FFFFFFFF00000000", block.getVendorInfoMask());
    }

    private void assertDeviceStateSectionAgilex(List<BaseEvidenceBlock> blocks) {
        final BaseEvidenceBlock block = blocks.get(4);
        Assertions.assertEquals(VENDOR, block.getVendor());
        Assertions.assertEquals("2.16.840.1.113741.1.15.4.1", block.getType());
        Assertions.assertEquals("2", block.getLayer());
        Assertions.assertEquals("0000000003000000", block.getVendorInfo());
        Assertions.assertEquals("FFFFFFFF000000FF", block.getVendorInfoMask());
    }

    private void assertSecondPrSectionAgilex(List<BaseEvidenceBlock> blocks) {
        final BaseEvidenceBlock block = blocks.get(5);
        Assertions.assertEquals(VENDOR, block.getVendor());
        Assertions.assertEquals("2.16.840.1.113741.1.15.4.6", block.getType());
        Assertions.assertEquals("2", block.getLayer());
        Assertions.assertEquals(33554432, block.getIndex());
        Assertions.assertEquals(1, block.getFwids().size());

        final FwIdField fwIds = block.getFwids().get(0);
        Assertions.assertEquals(FWIDS_HASH_ALG, fwIds.getHashAlg());
        Assertions.assertEquals("EDCB0F4721E6578D900E4C24AD4B19E194AB6C87F8243BFC6B11"
            + "754DD8B0BBDE4F30B1D18197932B6376DA004DCD97C4", fwIds.getDigest());
    }

    private void assertUntypedSectionLayer0Agilex(List<BaseEvidenceBlock> blocks) {
        final BaseEvidenceBlock block = blocks.get(6);
        Assertions.assertEquals(VENDOR, block.getVendor());
        Assertions.assertEquals("Agilex", block.getModel());
        Assertions.assertEquals("0", block.getLayer());
        Assertions.assertEquals(1, block.getFwids().size());

        final FwIdField fwIds = block.getFwids().get(0);
        Assertions.assertEquals(FWIDS_HASH_ALG, fwIds.getHashAlg());
        Assertions.assertEquals("CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B"
            + "605A43FF5BED8086072BA1E7CC2358BAECA134C825A7", fwIds.getDigest());
    }

    private void assertUntypedSectionLayer2Agilex(List<BaseEvidenceBlock> blocks) {
        final BaseEvidenceBlock block = blocks.get(7);
        Assertions.assertEquals(VENDOR, block.getVendor());
        Assertions.assertEquals("2.16.840.1.113741.1.15.4.12", block.getType());
        Assertions.assertEquals("2", block.getLayer());
        Assertions.assertEquals(1, block.getFwids().size());

        final FwIdField fwIds = block.getFwids().get(0);
        Assertions.assertEquals(FWIDS_HASH_ALG, fwIds.getHashAlg());
        Assertions.assertEquals("180C325CCCB299E76EC6C03A5B5A7755AF8EF499906DBF531F18"
            + "D0CA509E4871B0805CAC0F122B962D54BADC6119F3CF", fwIds.getDigest());
    }
}
