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

package com.intel.bkp.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.utils.EscapeUtils.escape;

class EscapeUtilsTest {
    @Test
    void givenStringWithManySlashes_whenEscaping_escapeAllByDoubleTheAmount() {
        final String given = "one \\ test \\\\ string \\\\\\";

        final String expected = "one \\\\ test \\\\\\\\ string \\\\\\\\\\\\";

        Assertions.assertEquals(expected, escape(given));
    }

    @Test
    void givenStringWithQuotes_whenEscaping_escapeAllQuotes() {
        final String given = "\"This type of code, related to regex etc., should be especially well tested\"";

        final String expected = "\\\"This type of code, related to regex etc., should be especially well tested\\\"";

        Assertions.assertEquals(expected, escape(given));
    }

    @Test
    void givenStringWithWhiteCharacters_whenEscaping_escapeAllWhiteCharacters() {
        final String given = "one \n test \t string \r\nsecond line";

        final String expected = "one \\n test \\t string \\r\\nsecond line";

        Assertions.assertEquals(expected, escape(given));
    }

    @Test
    void givenStringWithWhiteCharactersAndQuotes_whenEscaping_escapeAllWhiteCharactersAndQuotes() {
        final String given = "one \n\"test\"\t \\\"string\"\\ \r\nsecond line";

        final String expected = "one \\n\\\"test\\\"\\t \\\\\\\"string\\\"\\\\ \\r\\nsecond line";

        Assertions.assertEquals(expected, escape(given));
    }
}
