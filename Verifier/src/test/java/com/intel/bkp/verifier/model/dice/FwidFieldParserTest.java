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

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.verifier.model.dice.FieldParserTestUtils.getAsn1ObjectIdentifier;
import static com.intel.bkp.verifier.model.dice.FieldParserTestUtils.getOctetString;
import static com.intel.bkp.verifier.model.dice.FieldParserTestUtils.getSequence;

class FwidFieldParserTest {

    private static final String EXPECTED_HASH_ALG = "1.2.3.4";
    private static final String EXPECTED_DIGEST = "01020304";
    private static final FwIdField EXPECTED = new FwIdField(EXPECTED_HASH_ALG, EXPECTED_DIGEST);

    private static final ASN1Primitive HASH_ALG_OBJ = getAsn1ObjectIdentifier(EXPECTED_HASH_ALG);
    private static final ASN1Primitive DIGEST_OBJ = getOctetString(EXPECTED_DIGEST);

    private final FwidFieldParser sut = new FwidFieldParser();

    @Test
    void parse() {
        // given
        final ASN1TaggedObject taggedObj = getSequence(HASH_ALG_OBJ, DIGEST_OBJ);

        // when
        final FwIdField result = sut.parse(taggedObj);

        // then
        Assertions.assertEquals(EXPECTED, result);
    }

    @Test
    void parse_HashAlgNotSet() {
        // given
        final ASN1TaggedObject taggedObj = getSequence(DIGEST_OBJ);

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> sut.parse(taggedObj));
    }

    @Test
    void parse_DigestNotSet() {
        // given
        final ASN1TaggedObject taggedObj = getSequence(HASH_ALG_OBJ);

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> sut.parse(taggedObj));
    }
}
