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

package com.intel.bkp.fpgacerts.dice.ueid;

import com.intel.bkp.crypto.asn1.Asn1ParsingUtils;
import com.intel.bkp.fpgacerts.model.AttFamily;
import com.intel.bkp.fpgacerts.utils.BaseExtensionParser;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;

import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_UEID;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
@Getter
public class UeidExtensionParser extends BaseExtensionParser<UeidExtension> {

    private static final String EXTENSION_NAME = "UEID";
    private static final int UEID_EXTENSION_SIZE = 16;

    public UeidExtensionParser() {
        super(EXTENSION_NAME);
    }

    public UeidExtension parse(@NonNull final X509Certificate certificate) {
        return parse((X509Extension) certificate);
    }

    @Override
    protected UeidExtension parse(@NonNull final X509Extension x509Obj) {
        logExtensionParsingStart(x509Obj, "UEID");

        final var familyId = new byte[1];
        final var uid = new byte[8];
        ByteBufferSafe.wrap(getUeidExtensionValue(x509Obj))
            .skip(1) // typeCode
            .skip(3) // intelOui
            .skip(2) // reserved
            .get(familyId)
            .skip(1) // testMode
            .get(uid);

        final var attFamily = AttFamily.from(familyId[0]);

        log.trace("Parsed UEID Extension. FAMILY_NAME = {}, UID = {}",
            attFamily.getFamilyName(), toHex(uid));

        return new UeidExtension(attFamily.getFamilyId(), attFamily.getFamilyName(), uid);
    }

    private byte[] getUeidExtensionValue(final X509Extension x509Obj) {
        return getExtension(x509Obj, TCG_DICE_UEID.getOid())
            .map(Asn1ParsingUtils::parseSingleElementSequence)
            .map(Asn1ParsingUtils::parseOctetString)
            .filter(v -> UEID_EXTENSION_SIZE == v.length)
            .orElseThrow(() -> new IllegalArgumentException(getExtensionParsingError(x509Obj)));
    }
}
