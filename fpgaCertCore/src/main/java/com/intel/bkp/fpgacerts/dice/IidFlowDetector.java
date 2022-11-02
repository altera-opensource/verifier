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

package com.intel.bkp.fpgacerts.dice;

import com.intel.bkp.fpgacerts.dice.ueid.UeidExtensionParser;
import lombok.RequiredArgsConstructor;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.model.AttFamily.AGILEX;

@RequiredArgsConstructor
public class IidFlowDetector {

    private final UeidExtensionParser ueidExtensionParser;
    private Optional<Boolean> onlyEfuseUds = Optional.empty();

    public IidFlowDetector() {
        this(new UeidExtensionParser());
    }

    public IidFlowDetector withOnlyEfuseUds(boolean onlyEfuseUds) {
        this.onlyEfuseUds = Optional.of(onlyEfuseUds);
        return this;
    }

    public boolean isIidFlow(X509Certificate certificate) {
        return notOnlyEfuseUds() && isAgilex(certificate);
    }

    private Boolean notOnlyEfuseUds() {
        return onlyEfuseUds.map(x -> !x).orElse(true);
    }

    private boolean isAgilex(final X509Certificate certificate) {
        return AGILEX.getFamilyId() == ueidExtensionParser.parse(certificate).getFamilyId();
    }
}
