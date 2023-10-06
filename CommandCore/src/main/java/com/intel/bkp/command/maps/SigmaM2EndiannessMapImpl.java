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

import static com.intel.bkp.command.model.StructureField.SIGMA_M2_BKPS_DH_PUB_KEY;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_DEVICE_DH_PUB_KEY;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_DEVICE_UNIQUE_ID;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_MAC;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_MAGIC;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_PUBLIC_EFUSE_VALUES;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_RESERVED_HEADER;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_ROM_VERSION_NUM;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_SDM_FW_BUILD_ID;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_SDM_FW_SECURITY_VERSION_NUM;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_SDM_SESSION_ID;
import static com.intel.bkp.command.model.StructureField.SIGMA_M2_SIGNATURE;
import static com.intel.bkp.utils.ByteSwapOrder.CONVERT;
import static com.intel.bkp.utils.ByteSwapOrder.NONE;

public final class SigmaM2EndiannessMapImpl extends BaseEndiannessMapImpl {

    public SigmaM2EndiannessMapImpl(EndiannessActor actor) {
        super(actor);
    }

    @Override
    protected void populateFirmwareMap() {
        put(SIGMA_M2_RESERVED_HEADER, NONE);
        put(SIGMA_M2_MAGIC, CONVERT);
        put(SIGMA_M2_SDM_SESSION_ID, CONVERT);
        put(SIGMA_M2_DEVICE_UNIQUE_ID, NONE);
        put(SIGMA_M2_ROM_VERSION_NUM, CONVERT);
        put(SIGMA_M2_SDM_FW_BUILD_ID, NONE);
        put(SIGMA_M2_SDM_FW_SECURITY_VERSION_NUM, CONVERT);
        put(SIGMA_M2_PUBLIC_EFUSE_VALUES, CONVERT);
        put(SIGMA_M2_DEVICE_DH_PUB_KEY, NONE);
        put(SIGMA_M2_BKPS_DH_PUB_KEY, NONE);
        put(SIGMA_M2_SIGNATURE, CONVERT);
        put(SIGMA_M2_MAC, NONE);
    }

}

