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

class PathUtilsTest {

    private static final String EXPECTED_PATH_WITH_SLASH = "/test/path/";
    private static final String EXPECTED_PATH_NO_SLASH = "/test/path";

    private static final String EXPECTED_BASE_FILE_NAME = "xyz";

    @Test
    void checkTrailingSlash_WithTrailingSlash_DoNothing() {
        // when
        final String result = PathUtils.checkTrailingSlash(EXPECTED_PATH_WITH_SLASH);

        // then
        Assertions.assertEquals(EXPECTED_PATH_WITH_SLASH, result);
    }

    @Test
    void checkTrailingSlash_WithoutTrailingSlash_Success() {
        // when
        final String result = PathUtils.checkTrailingSlash(EXPECTED_PATH_NO_SLASH);

        // then
        Assertions.assertEquals(EXPECTED_PATH_WITH_SLASH, result);
    }

    @Test
    void checkTrailingSlash_NullPath_ReturnsEmptyString() {
        // when
        final String result = PathUtils.checkTrailingSlash(null);

        // then
        Assertions.assertEquals("", result);
    }

    @Test
    void removeTrailingSlash_WithTrailingSlash_Success() {
        // when
        final String result = PathUtils.removeTrailingSlash(EXPECTED_PATH_WITH_SLASH);

        // then
        Assertions.assertEquals(EXPECTED_PATH_NO_SLASH, result);
    }

    @Test
    void removeTrailingSlash_WithoutTrailingSlash_DoNothing() {
        // when
        final String result = PathUtils.removeTrailingSlash(EXPECTED_PATH_NO_SLASH);

        // then
        Assertions.assertEquals(EXPECTED_PATH_NO_SLASH, result);
    }

    @Test
    void buildPath_NoSlashes_Success() {
        // given
        final String expected = "test/path";

        // when
        final String result = PathUtils.buildPath("test", "path");

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void buildPath_WithSlashes_Success() {
        // given
        final String expected = "test/path";

        // when
        final String result = PathUtils.buildPath("test/", "path/");

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void buildPath_WithBlankFirstFragment_Success() {
        // given
        final String expected = "path";

        // when
        final String result = PathUtils.buildPath(" ", "path");

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void buildPath_WithEmptyMiddleFragment_Success() {
        // given
        final String expected = "test/path";

        // when
        final String result = PathUtils.buildPath("test", "", "path");

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void buildPath_WithNullLastFragment_Success() {
        // given
        final String expected = "test";

        // when
        final String result = PathUtils.buildPath("test", null);

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void getFileNameWithoutExtension_WithLongPath_ResultOnlyBaseName() {
        // given
        final String path = String.format("/long/path/to/file/%s.cer", EXPECTED_BASE_FILE_NAME);

        // when
        final String result = PathUtils.getFileNameWithoutExtension(path);

        // then
        Assertions.assertEquals(EXPECTED_BASE_FILE_NAME, result);
    }

    @Test
    void getFileNameWithoutExtension_WithLongPath_WithoutExtension_ResultOnlyBaseName() {
        // given
        final String path = String.format("/long/path/to/file/%s", EXPECTED_BASE_FILE_NAME);

        // when
        final String result = PathUtils.getFileNameWithoutExtension(path);

        // then
        Assertions.assertEquals(EXPECTED_BASE_FILE_NAME, result);
    }

    @Test
    void getFileNameWithoutExtension_WithOnlyFileName_WithExtension_ResultOnlyBaseName() {
        // given
        final String path = String.format("%s.cer", EXPECTED_BASE_FILE_NAME);

        // when
        final String result = PathUtils.getFileNameWithoutExtension(path);

        // then
        Assertions.assertEquals(EXPECTED_BASE_FILE_NAME, result);
    }

    @Test
    void getFileNameWithoutExtension_WithNotPrefixedPath_ResultOnlyBaseName() {
        // given
        final String path = String.format("test/%s.cer", EXPECTED_BASE_FILE_NAME);

        // when
        final String result = PathUtils.getFileNameWithoutExtension(path);

        // then
        Assertions.assertEquals(EXPECTED_BASE_FILE_NAME, result);
    }
}
