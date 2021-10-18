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
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@AllArgsConstructor
@NoArgsConstructor
public class RimToTcbInfoMapper {

    private BaseEvidenceBlockToTcbInfoMapper blockToTcbInfoMapper = new BaseEvidenceBlockToTcbInfoMapper();

    public List<TcbInfo> map(Rim rim) {
        return Optional.ofNullable(rim.getRimRecords())
            .map(RimRecords::getRecords)
            .map(this::toTcbInfo)
            .orElseGet(this::getEmptyList);
    }

    private List<TcbInfo> toTcbInfo(List<BaseEvidenceBlock> records) {
        return records
            .stream()
            .map(blockToTcbInfoMapper::map)
            .collect(Collectors.toList());
    }

    private List<TcbInfo> getEmptyList() {
        log.warn("List of expected measurements in RIM is empty or they cannot be mapped to TcbInfo structures.");
        return Collections.emptyList();
    }
}
