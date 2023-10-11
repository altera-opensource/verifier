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

package com.intel.bkp.verifier.rim.service;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import com.intel.bkp.verifier.rim.model.BaseEvidenceBlock;
import com.intel.bkp.verifier.rim.model.BaseEvidenceBlockToTcbInfoMapper;
import com.intel.bkp.verifier.rim.model.Rim;
import com.intel.bkp.verifier.rim.model.RimRecords;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RimToTcbInfoMeasurementsMapperTest {

    private final List<BaseEvidenceBlock> records = new ArrayList<>();

    @Mock
    private Rim rim;

    @Mock
    private RimRecords rimRecords;

    @Mock
    private BaseEvidenceBlock block;

    @Mock
    private TcbInfo tcbInfo;

    @Mock
    private BaseEvidenceBlockToTcbInfoMapper blockToTcbInfoMapper;

    @InjectMocks
    private RimToTcbInfoMeasurementsMapper sut;

    @Test
    void map_WithNullRimRecord_ReturnsEmptyList() {
        // when
        final List<TcbInfoMeasurement> result = sut.map(rim);

        // then
        assertEquals(0, result.size());
    }

    @Test
    void map_WithNullRecords_ReturnsEmptyList() {
        // given
        when(rim.getRimRecords()).thenReturn(rimRecords);

        // when
        final List<TcbInfoMeasurement> result = sut.map(rim);

        // then
        assertEquals(0, result.size());
    }

    @Test
    void map_WithNoRecords_ReturnsEmptyList() {
        // given
        when(rim.getRimRecords()).thenReturn(rimRecords);
        when(rimRecords.getRecords()).thenReturn(records);

        // when
        final List<TcbInfoMeasurement> result = sut.map(rim);

        // then
        assertEquals(0, result.size());
    }

    @Test
    void map_With1Record_Returns1TcbInfoMeasurement() {
        // given
        when(rim.getRimRecords()).thenReturn(rimRecords);
        when(rimRecords.getRecords()).thenReturn(records);
        records.add(block);
        when(blockToTcbInfoMapper.map(block)).thenReturn(tcbInfo);

        // when
        final List<TcbInfoMeasurement> result = sut.map(rim);

        // then
        assertEquals(1, result.size());
        assertEquals(new TcbInfoMeasurement(tcbInfo), result.get(0));
    }
}
