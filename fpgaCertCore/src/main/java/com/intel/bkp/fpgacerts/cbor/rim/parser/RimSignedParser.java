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

package com.intel.bkp.fpgacerts.cbor.rim.parser;

import com.intel.bkp.fpgacerts.cbor.CborParserBase;
import com.intel.bkp.fpgacerts.cbor.CborSignedBase;
import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RimSignedParser extends CborParserBase<RimSigned> {

    public static RimSignedParser instance() {
        return new RimSignedParser();
    }

    @Override
    public RimSigned parse(CBORObject cbor) {
        final var protectedDataRaw = toHex(cbor.get(CborSignedBase.CBOR_PROTECTED_DATA_KEY).GetByteString());
        final String unprotectedData = null; // cbor.get(RimSigned.CBOR_UNPROTECTED_DATA_KEY).get(0)
        final var payload = toHex(cbor.get(CborSignedBase.CBOR_PAYLOAD_KEY).GetByteString());
        final var signature = toHex(cbor.get(CborSignedBase.CBOR_SIGNATURE_KEY).GetByteString());
        return RimSigned.builder()
            .protectedData(RimProtectedHeaderParser.instance().parse(fromHex(protectedDataRaw)))
            .unprotectedData(unprotectedData)
            .payload(RimUnsignedParser.instance().parse(fromHex(payload)))
            .signature(signature)
            .build();
    }
}
