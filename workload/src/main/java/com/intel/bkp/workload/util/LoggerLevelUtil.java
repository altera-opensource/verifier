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

package com.intel.bkp.workload.util;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;

import java.util.Optional;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class LoggerLevelUtil {

    private static final String VERIFIER_LOGGER_NAME = "com.intel.bkp.verifier";
    private static final String FPGACERTS_LOGGER_NAME = "com.intel.bkp.fpgacerts";
    private static final String CRYPTO_LOGGER_NAME = "com.intel.bkp.crypto";

    public static void setLogLevel(String logLevel) {
        final Level level = Optional.ofNullable(logLevel)
            .map(Level::valueOf)
            .orElse(Level.INFO);

        setLevel(level, getLogger(Logger.ROOT_LOGGER_NAME));
        setLevel(level, getLogger(VERIFIER_LOGGER_NAME));
        setLevel(level, getLogger(FPGACERTS_LOGGER_NAME));
        setLevel(level, getLogger(CRYPTO_LOGGER_NAME));

        log.info("[WORKLOAD] LogLevel set to {}.", level);
    }

    private static Logger getLogger(String rootLoggerName) {
        return (Logger) LoggerFactory.getLogger(rootLoggerName);
    }

    private static void setLevel(Level level, Logger logger) {
        logger.setLevel(level);
    }
}
