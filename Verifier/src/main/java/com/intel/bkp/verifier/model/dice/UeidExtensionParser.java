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

import com.intel.bkp.ext.core.manufacturing.model.AttFamily;
import com.intel.bkp.ext.utils.ByteBufferSafe;
import com.intel.bkp.verifier.interfaces.ICertificateParser;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static com.intel.bkp.ext.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_UEID;

@Slf4j
@Getter
public class UeidExtensionParser extends BaseExtensionParser implements ICertificateParser {

    private static final int UEID_EXTENSION_SIZE = 16;
    private static final String FAILED_TO_PARSE_MESSAGE = "Failed to parse UEID Extension from certificate.";

    private UeidExtension ueidExtension;

    @Override
    public void parse(@NonNull X509Certificate certificate) {
        log.debug("Parsing UEID Extension from certificate: {}", certificate.getSubjectDN());

        final var familyId = new byte[1];
        final var uid = new byte[8];
        ByteBufferSafe.wrap(getUeidExtensionValue(certificate))
            .skip(1) // typeCode
            .skip(3) // intelOui
            .skip(2) // reserved
            .get(familyId)
            .skip(1) // testMode
            .get(uid);

        final var attFamily = AttFamily.from(familyId[0]);
        ueidExtension = new UeidExtension(attFamily.getFamilyId(), attFamily.getFamilyName(), uid);
        log.debug("Parsed UEID Extension from certificate. FAMILY_NAME = {}, UID = {}",
            attFamily.getFamilyName(), toHex(uid));
    }

    private byte[] getUeidExtensionValue(final X509Certificate certificate) {
        return Optional.of(certificate)
            .map(c -> c.getExtensionValue(TCG_DICE_UEID.getOid()))
            .map(this::parseExtension)
            .map(this::parseSequence)
            .map(seq -> seq.getObjectAt(0))
            .map(this::parseOctetString)
            .filter(v -> UEID_EXTENSION_SIZE == v.length)
            .orElseThrow(() -> new IllegalArgumentException(FAILED_TO_PARSE_MESSAGE));
    }

    @Override
    protected String getExtensionParsingError() {
        return FAILED_TO_PARSE_MESSAGE;
    }
}
