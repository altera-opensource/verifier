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

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.model.evidence.BaseEvidenceBlock;
import com.intel.bkp.verifier.model.evidence.Rim;
import com.intel.bkp.verifier.model.evidence.RimRecords;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EvidenceVerifierTest {

    private static final String REF_MEASUREMENT = "test";
    private static final String VENDOR = "VENDOR";
    private static final String VENDOR_INFO = "0000000003000000";
    private static final String VENDOR_INFO_INVALID = "1111111111111111";
    private static final String VENDOR_INFO_MASK = "FFFFFFFF000000FF";
    private static final int INDEX = 0;
    private static final TcbInfo TCB_INFO = new TcbInfo(Map.of(TcbInfoField.VENDOR, VENDOR,
        TcbInfoField.VENDOR_INFO, new MaskedVendorInfo(VENDOR_INFO, VENDOR_INFO_MASK)));
    private final Map<TcbInfoKey, TcbInfoValue> tcbInfoResponseMap = new HashMap<>();

    @Mock
    private BaseEvidenceBlock block;

    @Mock
    private TcbInfoAggregator tcbInfoAggregator;

    @Mock
    private RimParser rimParser;

    @Mock
    private RimToTcbInfoMapper rimMapper;

    @InjectMocks
    private EvidenceVerifier sut;

    @Test
    void verify_WithEmptyBlocks_ReturnsOk() {
        // given
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(mockEmptyRim());

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, REF_MEASUREMENT);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.OK, result);
    }

    @Test
    void verify_ThrowsException_ReturnsError() {
        // given
        doThrow(new IllegalArgumentException()).when(rimParser).parse(REF_MEASUREMENT);

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, REF_MEASUREMENT);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.ERROR, result);
    }

    @Test
    void verify_ValidatesBlockAndReturnsOk() {
        // given
        when(rimMapper.map(any())).thenReturn(List.of(TCB_INFO));
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(mockRim());
        mockResponse();

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, REF_MEASUREMENT);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.OK, result);
    }

    @Test
    void verify_ValidationFailsDueToKeyNotFound_ReturnsFail() {
        // given
        when(rimMapper.map(any())).thenReturn(List.of(TCB_INFO));
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(mockRim());

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, REF_MEASUREMENT);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.FAIL, result);
    }

    @Test
    void verify_ValidationFailsDueToWrongValue_ReturnsFail() {
        // given
        when(rimMapper.map(any())).thenReturn(List.of(TCB_INFO));
        when(rimParser.parse(REF_MEASUREMENT)).thenReturn(mockRim());
        mockWrongResponse();

        // when
        final VerifierExchangeResponse result = sut.verify(tcbInfoAggregator, REF_MEASUREMENT);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.FAIL, result);
    }

    private Rim mockEmptyRim() {
        return new Rim();
    }

    private Rim mockRim() {
        final RimRecords rimRecords = new RimRecords(List.of(block));
        return new Rim(rimRecords);
    }

    private void mockResponse() {
        mockResponseCommon(VENDOR_INFO);
    }

    private void mockWrongResponse() {
        mockResponseCommon(VENDOR_INFO_INVALID);
    }

    private void mockResponseCommon(String maskedVendorInfo) {
        final TcbInfoKey key = new TcbInfoKey();
        key.setVendor(VENDOR);
        key.setIndex(INDEX);

        final TcbInfoValue value = new TcbInfoValue();
        value.setMaskedVendorInfo(new MaskedVendorInfo(maskedVendorInfo));
        tcbInfoResponseMap.put(key, value);

        when(tcbInfoAggregator.getMap()).thenReturn(tcbInfoResponseMap);
    }
}
