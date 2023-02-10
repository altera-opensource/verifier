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

package com.intel.bkp.fpgacerts.dice.tcbinfo.verification;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

@Slf4j
public abstract class TcbInfoFieldVerifierBase<T> implements ITcbInfoFieldVerifier {

    protected final TcbInfoField field;
    private final boolean isFieldRequired;

    protected TcbInfoFieldVerifierBase(TcbInfoField field, boolean isFieldRequired) {
        this.field = field;
        this.isFieldRequired = isFieldRequired;
    }

    protected abstract boolean isValueValid(T value, TcbInfo tcbInfo);

    protected abstract String getExpected();

    public boolean verify(TcbInfo tcbInfo) {
        final Optional<T> fieldValue = tcbInfo.get(field);
        if (fieldValue.isEmpty()) {
            if (isFieldRequired) {
                log.error("TcbInfo does not contain required {} field.", field.toString());
                return false;
            }
            return true;
        }

        final T value = fieldValue.get();
        final boolean valid = isValueValid(value, tcbInfo);
        if (!valid) {
            log.error("TcbInfo contains incorrect {} field value.\nExpected: {}\nActual: {}",
                field.toString(), getExpected(), value);
        }

        return valid;
    }
}
