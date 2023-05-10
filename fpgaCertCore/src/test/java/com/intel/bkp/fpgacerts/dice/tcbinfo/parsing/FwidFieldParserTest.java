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

package com.intel.bkp.fpgacerts.dice.tcbinfo.parsing;

import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.FieldParserTestUtils.getAsn1ObjectIdentifier;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.FieldParserTestUtils.getFwIdSequence;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.FieldParserTestUtils.getFwIdsSequence;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.FieldParserTestUtils.getOctetString;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.FieldParserTestUtils.getSequence;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.parsing.FieldParserTestUtils.getTaggedSequence;

class FwidFieldParserTest {

    private static final String EXPECTED_HASH_ALG = "1.2.3.4";
    private static final String EXPECTED_DIGEST = "01020304";
    private static final String DUMMY_DATA = "DEADBEEF";
    private static final FwIdField EXPECTED = new FwIdField(EXPECTED_HASH_ALG, EXPECTED_DIGEST);

    private static final ASN1ObjectIdentifier HASH_ALG_OBJ = getAsn1ObjectIdentifier(EXPECTED_HASH_ALG);
    private static final DEROctetString DIGEST_OBJ = getOctetString(EXPECTED_DIGEST);
    private static final DEROctetString DUMMY_OBJ = getOctetString(DUMMY_DATA);

    private final FwidFieldParser sut = new FwidFieldParser();

    @Test
    void parse() {
        // given
        final ASN1TaggedObject taggedObj = getFwIdsSequence(getFwIdSequence(HASH_ALG_OBJ, DIGEST_OBJ));

        // when
        final FwIdField result = sut.parse(taggedObj);

        // then
        Assertions.assertEquals(EXPECTED, result);
    }

    @Test
    void parse_WithMultipleFwId_ThrowsException() {
        // given
        final String expectedMessage =
            "FwIds field contains multiple FwId values: [[1.2.3.4, #01020304], [1.2.3.4, #01020304]]";
        final ASN1TaggedObject taggedObj = getFwIdsSequence(
            getFwIdSequence(HASH_ALG_OBJ, DIGEST_OBJ),
            getFwIdSequence(HASH_ALG_OBJ, DIGEST_OBJ)
        );

        // when-then
        final IllegalArgumentException exception =
            Assertions.assertThrows(IllegalArgumentException.class, () -> sut.parse(taggedObj));
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    void parse_WithNotASequenceElementInFwIds_ThrowsException() {
        // given
        final String expectedMessage =
            "FwIds field contains element that is not an FwId: [[1.2.3.4, #01020304], #01020304]";
        final ASN1TaggedObject taggedObj = getTaggedSequence(
            getFwIdSequence(HASH_ALG_OBJ, DIGEST_OBJ),
            DIGEST_OBJ
        );

        // when-then
        final IllegalArgumentException exception =
            Assertions.assertThrows(IllegalArgumentException.class, () -> sut.parse(taggedObj));
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    void parse_WithTooManyElementsInFwId_ThrowsException() {
        // given
        final String expectedMessage = "FwId contains too many elements: [1.2.3.4, #01020304, #deadbeef]";
        final ASN1TaggedObject taggedObj = getFwIdsSequence(getSequence(HASH_ALG_OBJ, DIGEST_OBJ, DUMMY_OBJ));

        // when-then
        final IllegalArgumentException exception =
            Assertions.assertThrows(IllegalArgumentException.class, () -> sut.parse(taggedObj));
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    void parse_HashAlgNotSet() {
        // given
        final String expectedMessage = "FwIds field does not contain hashAlg or digest: [#01020304]";
        final ASN1TaggedObject taggedObj = getFwIdsSequence(getSequence(DIGEST_OBJ));

        // when-then
        final IllegalArgumentException exception =
            Assertions.assertThrows(IllegalArgumentException.class, () -> sut.parse(taggedObj));
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    void parse_DigestNotSet() {
        // given
        final String expectedMessage = "FwIds field does not contain hashAlg or digest: [1.2.3.4]";
        final ASN1TaggedObject taggedObj = getFwIdsSequence(getSequence(HASH_ALG_OBJ));

        // when-then
        final IllegalArgumentException exception =
            Assertions.assertThrows(IllegalArgumentException.class, () -> sut.parse(taggedObj));
        Assertions.assertEquals(expectedMessage, exception.getMessage());
    }
}
