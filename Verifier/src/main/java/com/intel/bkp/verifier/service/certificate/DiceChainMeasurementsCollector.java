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

package com.intel.bkp.verifier.service.certificate;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoExtensionParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurement;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public class DiceChainMeasurementsCollector {

    private final TcbInfoExtensionParser tcbInfoExtensionParser;

    public DiceChainMeasurementsCollector() {
        this(new TcbInfoExtensionParser());
    }

    public List<TcbInfoMeasurement> getMeasurementsFromCertChain(List<X509Certificate> fullChain) {
        log.info("*** COLLECTING MEASUREMENTS FROM CERTIFICATE CHAIN ***");
        return getTcbInfoMeasurements(fullChain);
    }

    private List<TcbInfoMeasurement> getTcbInfoMeasurements(List<X509Certificate> chain) {
        return chain.stream()
            .map(tcbInfoExtensionParser::parse)
            .flatMap(Collection::stream)
            .map(TcbInfoMeasurement::new)
            .toList();
    }
}
