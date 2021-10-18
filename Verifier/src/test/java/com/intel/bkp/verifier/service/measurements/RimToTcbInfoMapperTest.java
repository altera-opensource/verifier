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

package com.intel.bkp.verifier.service.measurements;

import com.intel.bkp.verifier.model.dice.TcbInfo;
import com.intel.bkp.verifier.model.evidence.BaseEvidenceBlock;
import com.intel.bkp.verifier.model.evidence.BaseEvidenceBlockToTcbInfoMapper;
import com.intel.bkp.verifier.model.evidence.Rim;
import com.intel.bkp.verifier.model.evidence.RimRecords;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RimToTcbInfoMapperTest {

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
    private RimToTcbInfoMapper sut;

    @Test
    void map_WithNullRimRecord_ReturnsEmptyList() {
        // when
        final List<TcbInfo> result = sut.map(rim);

        // then
        Assertions.assertEquals(0, result.size());
    }

    @Test
    void map_WithNullRecords_ReturnsEmptyList() {
        // given
        when(rim.getRimRecords()).thenReturn(rimRecords);

        // when
        final List<TcbInfo> result = sut.map(rim);

        // then
        Assertions.assertEquals(0, result.size());
    }

    @Test
    void map_WithNoRecords_ReturnsEmptyList() {
        // given
        when(rim.getRimRecords()).thenReturn(rimRecords);
        when(rimRecords.getRecords()).thenReturn(records);

        // when
        final List<TcbInfo> result = sut.map(rim);

        // then
        Assertions.assertEquals(0, result.size());
    }

    @Test
    void map_With1Record_Returns1TcbInfo() {
        // given
        when(rim.getRimRecords()).thenReturn(rimRecords);
        when(rimRecords.getRecords()).thenReturn(records);
        records.add(block);

        // when
        final List<TcbInfo> result = sut.map(rim);

        // then
        Assertions.assertEquals(1, result.size());
    }

    @Test
    void map_With1Record_BlockMapperIsCalled() {
        // given
        when(rim.getRimRecords()).thenReturn(rimRecords);
        when(rimRecords.getRecords()).thenReturn(records);
        records.add(block);
        when(blockToTcbInfoMapper.map(block)).thenReturn(tcbInfo);

        // when
        final List<TcbInfo> result = sut.map(rim);

        // then
        Assertions.assertEquals(tcbInfo, result.get(0));
    }
}
