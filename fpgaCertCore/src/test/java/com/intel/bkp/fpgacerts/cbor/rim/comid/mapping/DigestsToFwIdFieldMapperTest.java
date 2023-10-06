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

package com.intel.bkp.fpgacerts.cbor.rim.comid.mapping;

import com.intel.bkp.fpgacerts.cbor.rim.comid.Digest;
import com.intel.bkp.fpgacerts.dice.tcbinfo.FwIdField;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static com.intel.bkp.fpgacerts.cbor.rim.comid.mapping.DigestsToFwIdFieldMapper.HashAlgorithmRegistry.SHA384;
import static com.intel.bkp.fpgacerts.cbor.rim.comid.mapping.DigestsToFwIdFieldMapper.HashAlgorithmRegistry.SHA512;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DigestsToFwIdFieldMapperTest {

    private static final String HASH = "01020304050ABCDE0F";
    private static final String DIFFERENT_HASH = "FEDCBA9876543210";

    private final DigestsToFwIdFieldMapper sut = new DigestsToFwIdFieldMapper();

    @Test
    void map_WithEmptyDigests_ReturnsNull() {
        // when
        final FwIdField result = sut.map(List.of());

        // then
        assertNull(result);
    }

    @ParameterizedTest
    @EnumSource(value = DigestsToFwIdFieldMapper.HashAlgorithmRegistry.class)
    void map_WithSingleDigest_WithKnownHashAlgId_ReturnsFwId(DigestsToFwIdFieldMapper.HashAlgorithmRegistry hashAlg) {
        // given
        final Digest digest = new Digest(hashAlg.getId(), HASH);
        final FwIdField expected = new FwIdField(hashAlg.getOid(), HASH);

        // when
        final FwIdField result = sut.map(List.of(digest));

        // then
        assertEquals(expected, result);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 5, 123})
    void map_WithSingleDigest_WithUnknownHashAlgId_Throws(int hashAlgId) {
        // given
        final Digest digest = new Digest(hashAlgId, HASH);

        // when-then
        assertThrows(RuntimeException.class, () -> sut.map(List.of(digest)));
    }

    @Test
    void map_WithMultipleDigests_ReturnsFwIdBasedOnFirstDigest() {
        // given
        final var firstDigestAlg = SHA384;
        final var firstDigest = new Digest(firstDigestAlg.getId(), HASH);
        final var secondDigest = new Digest(SHA512.getId(), DIFFERENT_HASH);
        final var digests = List.of(firstDigest, secondDigest);
        final FwIdField expected = new FwIdField(firstDigestAlg.getOid(), firstDigest.getValue());


        // when
        final FwIdField result = sut.map(digests);

        // then
        assertEquals(expected, result);
    }
}
