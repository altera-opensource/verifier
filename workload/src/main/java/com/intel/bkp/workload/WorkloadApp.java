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

package com.intel.bkp.workload;

import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.workload.service.VerifierService;
import com.intel.bkp.workload.util.AppArgument;
import com.intel.bkp.workload.util.AppArgumentParser;
import com.intel.bkp.workload.util.LoggerLevelUtil;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class WorkloadApp {

    public static void main(String[] args) {
        int returnCode;
        try {
            final AppArgument appArgs = AppArgumentParser.parseArguments(args);
            log.info("[WORKLOAD] Running using commandline appArgs: {}", appArgs);
            setLogLevel(appArgs.getLogLevel());
            returnCode = new VerifierService().callVerifier(appArgs);
        } catch (Exception e) {
            log.error("[WORKLOAD] Exception occurred: {}", e.getMessage());
            log.debug("Stacktrace: ", e);
            returnCode = VerifierExchangeResponse.ERROR.getCode();
        }

        System.exit(returnCode);
    }

    private static void setLogLevel(String logLevel) {
        LoggerLevelUtil.setLogLevel(logLevel);
    }
}
