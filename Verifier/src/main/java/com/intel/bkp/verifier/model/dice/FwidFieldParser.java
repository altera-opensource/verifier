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

import com.intel.bkp.verifier.interfaces.ITcbInfoFieldParser;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;

import static com.intel.bkp.ext.utils.HexConverter.toHex;

@Slf4j
public class FwidFieldParser extends BaseExtensionParser implements ITcbInfoFieldParser<FwIdField> {

    private static final int ELEM_COUNT = 2;
    private static final String FAILED_TO_PARSE_MESSAGE = "Failed to parse FwId field from certificate.";

    @Override
    public FwIdField parse(ASN1TaggedObject object) {
        log.debug("Parsing FwId field from extension from certificate.");

        final FwIdField field = new FwIdField();
        final ASN1Sequence sequence = parseSequence(object.getObject(), ELEM_COUNT);

        sequence.forEach(obj -> mapToField(field, obj));

        if (!field.isSet()) {
            throw new IllegalArgumentException(String.format(
                "FwId field does not contain hashAlg or digest: %s", sequence));
        }

        return field;
    }

    @Override
    protected String getExtensionParsingError() {
        return FAILED_TO_PARSE_MESSAGE;
    }

    private void mapToField(FwIdField field, ASN1Encodable obj) {
        if (obj instanceof ASN1ObjectIdentifier) {
            field.setHashAlg(parseAsn1Identifier(obj));
        } else if (obj instanceof DEROctetString) {
            field.setDigest(toHex(parseOctetString(obj)));
        }
    }
}
