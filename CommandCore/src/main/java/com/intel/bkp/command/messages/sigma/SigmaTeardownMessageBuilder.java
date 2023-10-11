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

package com.intel.bkp.command.messages.sigma;

import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import lombok.Getter;

import static com.intel.bkp.command.model.Magic.SIGMA_TEARDOWN;
import static com.intel.bkp.utils.ByteSwapOrder.B2L;

@Getter
public class SigmaTeardownMessageBuilder {

    private static final int SESSION_UNKNOWN = -1;
    private static final int SDM_SESSION_ID_LEN = Integer.BYTES;

    private final byte[] reservedHeader = new byte[Integer.BYTES];
    private final byte[] magic = ByteSwap.getSwappedArray(SIGMA_TEARDOWN.getCode(), B2L);
    private final byte[] sdmSessionId = ByteSwap.getSwappedArray(SESSION_UNKNOWN, B2L);

    public SigmaTeardownMessageBuilder sdmSessionId(byte[] sdmSessionId) {
        ByteBufferSafe buffer = ByteBufferSafe.wrap(ByteSwap.getSwappedArrayByInt(sdmSessionId, B2L));
        buffer.getAll(this.sdmSessionId);
        return this;
    }

    public SigmaTeardownMessage build() {
        SigmaTeardownMessage sigmaTeardownMessage = new SigmaTeardownMessage();
        sigmaTeardownMessage.setReservedHeader(reservedHeader);
        sigmaTeardownMessage.setMagic(magic);
        sigmaTeardownMessage.setSdmSessionId(sdmSessionId);
        return sigmaTeardownMessage;
    }

    public SigmaTeardownMessageBuilder parse(byte[] message) {
        ByteBufferSafe.wrap(message)
            .get(reservedHeader)
            .get(magic)
            .getAll(sdmSessionId);
        return this;
    }
}
