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

package com.intel.bkp.verifier.model.dice;

import com.intel.bkp.ext.utils.ByteSwap;
import com.intel.bkp.ext.utils.ByteSwapOrder;
import com.intel.bkp.ext.utils.HexConverter;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;

@Slf4j
public class DiceParamsParser extends DiceParamsParserBase {

    @Getter
    private DiceParams diceParams;

    @Override
    public void parse(@NonNull X509Certificate certificate) {
        log.debug("Parsing DiceParams from certificate: {}", certificate.getSubjectDN());

        final String[] splitDN = parsePrincipalField(certificate, X509Certificate::getIssuerDN);

        final String ski = splitDN[3];
        final String uid = splitDN[4];
        diceParams = new DiceParams(ski, uid);

        // uid is used in diceParams on purpose
        // uidInLittleEndian is used to present it in logs in consistent format (as received from GET_CHIPID)
        final String uidInLittleEndian = HexConverter.toHex(ByteSwap.getSwappedArrayByLong(
            HexConverter.fromHex(uid), ByteSwapOrder.B2L));

        log.debug("Parsed DiceParams from certificate. SKI = {}, UID = {} (in format for Distribution Point: {})", ski,
            uidInLittleEndian, uid);
    }
}