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

package com.intel.bkp.verifier.transport.systemconsole;

import com.intel.bkp.verifier.transport.tcp.TcpConfig;
import lombok.Getter;
import lombok.experimental.SuperBuilder;

import java.util.Optional;

@Getter
@SuperBuilder
public class SystemConsoleConfig extends TcpConfig {

    private static final String ERROR_CABLE = "Error parsing cableID in transportID";
    private static final String PATTERN_CABLE = "cableID:([^;]*)";

    private Integer cableId;

    public SystemConsoleConfig(String transportId) {
        super(transportId);

        final String transportIdFormatted = removeWhitespaces(transportId);
        cableId = Optional.ofNullable(parseInteger(transportIdFormatted, PATTERN_CABLE, ERROR_CABLE))
            .map(SystemConsoleConfig::transformCableId)
            .orElse(null);
    }

    private static int transformCableId(int cableId) {
        // convert 1-indexing in workload application and verifier API
        // to 0-indexing used internally in Verifier for processing

        if (cableId < 1) {
            throw new IllegalArgumentException("CableID should be a positive integer.");
        }

        return cableId - 1;
    }
}
