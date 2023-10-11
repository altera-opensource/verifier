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

package com.intel.bkp.command.maps;

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.maps.BaseEndiannessMapImpl;

import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_ENCRYPTED_PAYLOAD;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_INITIAL_IV;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_MAC;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_MAGIC;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_MSG_RESP_COUNTER;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_PAYLOAD_LEN;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_RESERVED_HEADER;
import static com.intel.bkp.command.model.StructureField.SIGMA_ENC_SDM_SESSION_ID;
import static com.intel.bkp.utils.ByteSwapOrder.CONVERT;
import static com.intel.bkp.utils.ByteSwapOrder.NONE;

public class SigmaEncEndiannessMapImpl extends BaseEndiannessMapImpl {

    public SigmaEncEndiannessMapImpl(EndiannessActor actor) {
        super(actor);
    }

    @Override
    protected void populateFirmwareMap() {
        put(SIGMA_ENC_RESERVED_HEADER, NONE);
        put(SIGMA_ENC_MAGIC, CONVERT);
        put(SIGMA_ENC_SDM_SESSION_ID, CONVERT);
        put(SIGMA_ENC_MSG_RESP_COUNTER, CONVERT);
        put(SIGMA_ENC_PAYLOAD_LEN, CONVERT);
        put(SIGMA_ENC_INITIAL_IV, NONE);
        put(SIGMA_ENC_ENCRYPTED_PAYLOAD, NONE);
        put(SIGMA_ENC_MAC, NONE);
    }
}
