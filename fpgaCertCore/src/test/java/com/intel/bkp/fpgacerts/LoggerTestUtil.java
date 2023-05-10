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

package com.intel.bkp.fpgacerts;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;

public class LoggerTestUtil extends ListAppender<ILoggingEvent> {

    public static LoggerTestUtil instance(Class<?> testClass) {
        final Logger logger = (Logger) LoggerFactory.getLogger(testClass);

        final LoggerTestUtil loggerTestUtil = new LoggerTestUtil();
        loggerTestUtil.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
        logger.addAppender(loggerTestUtil);
        logger.setLevel(Level.TRACE);
        loggerTestUtil.start();

        return loggerTestUtil;
    }

    public void reset() {
        list.clear();
    }

    public boolean contains(String msg, Level logLevel) {
        return list.stream().anyMatch(event -> containsFilter(msg, logLevel, event));
    }

    public int getSize() {
        return list.size();
    }

    public long getSize(Level level) {
        return this.list.stream()
            .filter(event -> event.getLevel().equals(level))
            .count();
    }

    private static boolean containsFilter(String msg, Level logLevel, ILoggingEvent event) {
        return String.valueOf(event).contains(msg) && event.getLevel().equals(logLevel);
    }
}
