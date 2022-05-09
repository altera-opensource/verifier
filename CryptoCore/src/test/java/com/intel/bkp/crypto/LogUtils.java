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

package com.intel.bkp.crypto;

import com.github.valfirst.slf4jtest.LoggingEvent;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.slf4j.helpers.MessageFormatter;
import uk.org.lidalia.slf4jext.Level;

import java.util.stream.Stream;

import static com.github.valfirst.slf4jtest.TestLoggerFactory.getTestLogger;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class LogUtils {

    public static Stream<String> getLogs(Class<?> c, Level level) {
        return getLoggingEvents(c)
            .filter(event -> level == event.getLevel())
            .map(LogUtils::getFormattedMessage);
    }

    public static void clearLogs(Class<?> c) {
        getTestLogger(c).clear();
    }

    private static Stream<LoggingEvent> getLoggingEvents(Class<?> c) {
        return getTestLogger(c)
            .getLoggingEvents()
            .stream();
    }

    private static String getFormattedMessage(LoggingEvent event) {
        return MessageFormatter.arrayFormat(event.getMessage(), event.getArguments().toArray()).getMessage();
    }
}
