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

package com.intel.bkp.verifier.protocol.common.model;

import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;

import java.nio.ByteBuffer;

import static com.intel.bkp.utils.HexConverter.toHex;

public class DeviceStateMeasurementRecord {

    private static final int FLAGS_LEN = Integer.BYTES;
    private static final int COUNTERS_LEN = Integer.BYTES;

    private final byte[] flags = new byte[FLAGS_LEN];
    private final byte[] counters = new byte[COUNTERS_LEN];

    public DeviceStateMeasurementRecord(ByteBufferSafe buffer) {
        final byte[] flagsTmp = new byte[FLAGS_LEN];
        buffer.get(flagsTmp);
        buffer.get(this.counters);
        ByteBufferSafe.wrap(ByteSwap.getSwappedArrayByInt(flagsTmp, ByteSwapOrder.L2B))
            .get(this.flags);
    }

    public String getData() {
        return toHex(ByteBuffer.allocate(flags.length + counters.length)
            .put(flags)
            .put(counters)
            .array());
    }
}
