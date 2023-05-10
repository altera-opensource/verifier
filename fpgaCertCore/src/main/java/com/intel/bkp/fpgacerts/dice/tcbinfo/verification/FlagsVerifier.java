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

package com.intel.bkp.fpgacerts.dice.tcbinfo.verification;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoKey;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoValue;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.MeasurementType.CMF;

@Slf4j
public class FlagsVerifier extends TcbInfoFieldVerifierBase<String> {

    final boolean testModeSecrets;

    public FlagsVerifier(boolean testModeSecrets) {
        super(TcbInfoField.FLAGS, false);
        this.testModeSecrets = testModeSecrets;
    }

    @Override
    protected boolean isValueValid(String value, TcbInfo tcbInfo) {
        return testModeSecrets || !isCmfHashMeasurement(tcbInfo) || value.isEmpty();
    }

    @Override
    protected String getExpected() {
        return "Empty flags field or no flags field at all (for CMF hash TcbInfo - others are not validated)";
    }

    private boolean isCmfHashMeasurement(TcbInfo tcbInfo) {
        final Optional<String> model = tcbInfo.get(TcbInfoField.MODEL);
        final var verifier = MeasurementExistenceVerifier.instance(
            Map.of(TcbInfoKey.from(tcbInfo), TcbInfoValue.from(tcbInfo))
        );
        return verifier.isMeasurementPresent(model.orElse(""), CMF);
    }
}
