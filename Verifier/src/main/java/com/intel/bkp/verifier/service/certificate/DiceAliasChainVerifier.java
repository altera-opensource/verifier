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

import com.intel.bkp.fpgacerts.interfaces.ICrlProvider;
import com.intel.bkp.fpgacerts.verification.DiceChainVerifierBase;
import com.intel.bkp.verifier.exceptions.SigmaException;

import static com.intel.bkp.fpgacerts.model.Oid.KEY_PURPOSE_ATTEST_INIT;
import static com.intel.bkp.fpgacerts.model.Oid.KEY_PURPOSE_ATTEST_LOC;

public class DiceAliasChainVerifier extends DiceChainVerifierBase {

    public DiceAliasChainVerifier(ICrlProvider crlProvider, String trustedRootHash, boolean testModeSecrets) {
        super(crlProvider, trustedRootHash, testModeSecrets);
    }

    @Override
    protected String[] getExpectedLeafCertKeyPurposes() {
        return new String[]{KEY_PURPOSE_ATTEST_INIT.getOid(), KEY_PURPOSE_ATTEST_LOC.getOid()};
    }

    @Override
    protected void handleVerificationFailure(String failureDetails) {
        throw new SigmaException(failureDetails);
    }
}
