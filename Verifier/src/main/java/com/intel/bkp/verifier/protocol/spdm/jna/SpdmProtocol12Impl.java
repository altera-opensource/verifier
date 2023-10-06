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

package com.intel.bkp.verifier.protocol.spdm.jna;

import com.intel.bkp.protocol.spdm.jna.SpdmProtocol12;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.service.certificate.AppContext;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter(AccessLevel.PACKAGE)
public class SpdmProtocol12Impl extends SpdmProtocol12 {

    public SpdmProtocol12Impl() {
        super(new MessageSenderImpl(), new SpdmMessageResponseHandler(), new SpdmParametersProviderImpl());
    }

    @Override
    protected void initializeLibrary() {
        if (jnaInterface != null) {
            log.debug("SPDM Wrapper library already initialized.");
            return;
        }

        log.debug("Initializing SPDM Wrapper library.");

        try {
            this.jnaInterface = LibSpdmLibraryWrapperImpl.getInstance();
        } catch (UnsatisfiedLinkError e) {
            throw new VerifierRuntimeException("Failed to link SPDM Wrapper library.", e);
        }
    }

    @Override
    protected boolean isMeasurementsRequestSignature() {
        final AppContext appContext = AppContext.instance();
        return appContext.getLibConfig().getLibSpdmParams().isMeasurementsRequestSignature();
    }
}
