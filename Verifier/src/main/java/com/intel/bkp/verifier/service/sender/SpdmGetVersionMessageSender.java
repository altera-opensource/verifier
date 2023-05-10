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

package com.intel.bkp.verifier.service.sender;

import com.intel.bkp.verifier.exceptions.SpdmCommandFailedException;
import com.intel.bkp.verifier.exceptions.UnsupportedSpdmVersionException;
import com.intel.bkp.verifier.service.spdm.SpdmCaller;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SpdmGetVersionMessageSender {

    public static final String SPDM_SUPPORTED_VERSION = "12";

    public String send() throws UnsupportedSpdmVersionException, SpdmCommandFailedException {
        log.info("*** CHECKING SPDM RESPONDER VERSION ***");

        final String responderVersion = SpdmCaller.getInstance().getVersion();

        log.debug("SPDM Responder version: {}", responderVersion);

        if (toInt(SPDM_SUPPORTED_VERSION) != toInt(responderVersion)) {
            throw new UnsupportedSpdmVersionException(responderVersion, SPDM_SUPPORTED_VERSION);
        }

        return responderVersion;
    }

    private static int toInt(String responderVersion) {
        return Integer.parseInt(responderVersion, 16);
    }
}
