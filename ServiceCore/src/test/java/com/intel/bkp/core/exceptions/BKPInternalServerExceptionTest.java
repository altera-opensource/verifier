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

package com.intel.bkp.core.exceptions;

import com.intel.bkp.core.interfaces.IErrorCode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class BKPInternalServerExceptionTest {

    @Test
    void constructor_WithOnlyErrorCode_ReturnValidError() {
        final BKPInternalServerException exception = Assertions.assertThrows(BKPInternalServerException.class,
            this::throwError);
        Assertions.assertTrue(new BkpExceptionMatcher(getError()).matchesSafely(exception));
    }

    @Test
    void constructor_WithErrorCodeAndThrowable_ReturnValidError() {
        final BKPInternalServerException exception = Assertions.assertThrows(BKPInternalServerException.class,
            this::throwErrorWithCause);
        Assertions.assertTrue(new BkpExceptionMatcher(getError()).matchesSafely(exception));
    }

    @Test
    void constructor_WithErrorCodeAndInternalMessage_ReturnValidError() {
        // then
        final BKPInternalServerException exception = Assertions.assertThrows(BKPInternalServerException.class,
            this::throwErrorWithInternalMessage);
        Assertions.assertTrue(new BkpExceptionMatcher(getError()).matchesSafely(exception));
        Assertions.assertEquals("Test internal", exception.getMessage());
    }

    @Test
    void constructor_WithErrorCodeAndInternalMessageAndCause_ReturnValidError() {
        final BKPInternalServerException exception = Assertions.assertThrows(BKPInternalServerException.class,
            this::throwErrorWithCauseAndInternalMessage);
        Assertions.assertTrue(new BkpExceptionMatcher(getError()).matchesSafely(exception));
        Assertions.assertEquals("Test internal msg", exception.getMessage());
    }

    private void throwError() {
        throw new BKPInternalServerException(getError());
    }

    private void throwErrorWithInternalMessage() {
        throw new BKPInternalServerException(getError(), "Test internal");
    }

    private void throwErrorWithCause() {
        Exception cause = new RuntimeException("Some message");
        throw new BKPInternalServerException(getError(), cause);
    }

    private void throwErrorWithCauseAndInternalMessage() {
        Exception cause = new RuntimeException("Some message");
        throw new BKPInternalServerException(getError(), "Test internal msg", cause);
    }

    private IErrorCode getError() {
        return new IErrorCode() {
            @Override
            public int getCode() {
                return 10;
            }

            @Override
            public String getExternalMessage() {
                return "test";
            }
        };
    }
}
