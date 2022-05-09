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

package com.intel.bkp.verifier.service;

import com.intel.bkp.verifier.exceptions.InitSessionFailedException;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.sender.GetChipIdMessageSender;
import com.intel.bkp.verifier.service.sender.TeardownMessageSender;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor
public class InitSessionComponent {

    private TeardownMessageSender teardownMessageSender = new TeardownMessageSender();
    private GetChipIdMessageSender getChipIdMessageSender = new GetChipIdMessageSender();

    public byte[] initializeSessionForDeviceId() throws InitSessionFailedException {
        return initializeSessionForDeviceId(AppContext.instance());
    }

    @NonNull
    byte[] initializeSessionForDeviceId(AppContext appContext) throws InitSessionFailedException {

        final TransportLayer transportLayer = appContext.getTransportLayer();
        final CommandLayer commandLayer = appContext.getCommandLayer();

        teardownMessageSender.send(transportLayer, commandLayer);
        return Optional.ofNullable(getChipIdMessageSender.send(transportLayer, commandLayer))
            .orElseThrow(() -> new InitSessionFailedException("DeviceId is null."));
    }
}

