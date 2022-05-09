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

package com.intel.bkp.verifier.command.maps;


import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.verifier.endianess.EndianessStructureFields;

import static com.intel.bkp.utils.ByteSwapOrder.CONVERT;
import static com.intel.bkp.utils.ByteSwapOrder.NONE;

public final class GetMeasurementRspEndianessMapImpl extends BaseEndianessMapImpl {

    public GetMeasurementRspEndianessMapImpl(EndianessActor actor) {
        super(actor);
    }

    @Override
    void populateFirmwareMap() {
        put(EndianessStructureFields.GET_MEASUREMENT_MAGIC, CONVERT);
        put(EndianessStructureFields.GET_MEASUREMENT_SDM_SESSION_ID, CONVERT);
        put(EndianessStructureFields.GET_MEASUREMENT_DEVICE_UNIQUE_ID, NONE);
        put(EndianessStructureFields.GET_MEASUREMENT_ROM_VERSION_NUM, CONVERT);
        put(EndianessStructureFields.GET_MEASUREMENT_SDM_FW_BUILD_ID, NONE);
        put(EndianessStructureFields.GET_MEASUREMENT_SDM_FW_SECURITY_VERSION_NUM, CONVERT);
        put(EndianessStructureFields.GET_MEASUREMENT_PUBLIC_EFUSE_VALUES, CONVERT);
        put(EndianessStructureFields.GET_MEASUREMENT_DEVICE_DH_PUB_KEY, NONE);
        put(EndianessStructureFields.GET_MEASUREMENT_VERIFIER_DH_PUB_KEY, NONE);
        put(EndianessStructureFields.GET_MEASUREMENT_CMF_DESCRIPTOR_HASH, NONE);
        put(EndianessStructureFields.GET_MEASUREMENT_RECORD_LEN, CONVERT);
        put(EndianessStructureFields.GET_MEASUREMENT_MAC, NONE);
    }
}

