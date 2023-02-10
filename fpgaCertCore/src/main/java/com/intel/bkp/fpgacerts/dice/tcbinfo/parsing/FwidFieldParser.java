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

package com.intel.bkp.fpgacerts.dice.tcbinfo.parsing;

import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;

import java.util.Arrays;

import static com.intel.bkp.crypto.asn1.Asn1ParsingUtils.parseAsn1Identifier;
import static com.intel.bkp.crypto.asn1.Asn1ParsingUtils.parseOctetString;
import static com.intel.bkp.crypto.asn1.Asn1ParsingUtils.parseSequence;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.bouncycastle.asn1.BERTags.SEQUENCE;

@Slf4j
public class FwidFieldParser implements ITcbInfoFieldParser<FwIdField> {

    private static final int ELEM_COUNT = 2;

    @Override
    public FwIdField parse(ASN1TaggedObject object) {
        final FwIdField field = new FwIdField();
        final ASN1Sequence fwIdsSequence = parseSequence(object.getBaseUniversal(false, SEQUENCE));

        if (containsElementThatIsNotASequence(fwIdsSequence)) {
            throw new IllegalArgumentException("FwIds field contains element that is not an FwId: " + fwIdsSequence);
        }

        if (hasMultipleFwIds(fwIdsSequence)) {
            throw new IllegalArgumentException("FwIds field contains multiple FwId values: " + fwIdsSequence);
        }

        final ASN1Sequence fwIdSequence = (ASN1Sequence) fwIdsSequence.getObjectAt(0);
        if (hasTooManyElementsInSingleFwId(fwIdSequence)) {
            throw new IllegalArgumentException("FwId contains too many elements: " + fwIdSequence);
        }

        fwIdSequence.forEach(obj -> mapToField(field, obj));

        if (!field.isSet()) {
            throw new IllegalArgumentException(String.format(
                "FwIds field does not contain hashAlg or digest: %s", fwIdSequence));
        }

        return field;
    }

    private boolean containsElementThatIsNotASequence(ASN1Sequence sequence) {
        return !Arrays.stream(sequence.toArray()).allMatch(obj -> obj instanceof ASN1Sequence);
    }

    private boolean hasMultipleFwIds(ASN1Sequence sequence) {
        return sequence.size() > 1;
    }

    private boolean hasTooManyElementsInSingleFwId(ASN1Sequence sequence) {
        return sequence.size() > ELEM_COUNT;
    }

    private void mapToField(FwIdField field, ASN1Encodable obj) {
        if (obj instanceof ASN1ObjectIdentifier) {
            field.setHashAlg(parseAsn1Identifier(obj));
        } else if (obj instanceof DEROctetString) {
            field.setDigest(toHex(parseOctetString(obj)));
        }
    }
}
