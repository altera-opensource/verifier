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

package com.intel.bkp.command.model;

import com.intel.bkp.command.maps.CertificateResponseEndiannessMapImpl;
import com.intel.bkp.command.maps.CreateSubKeyRspEndiannessMapImpl;
import com.intel.bkp.command.maps.GetMeasurementRspEndiannessMapImpl;
import com.intel.bkp.command.maps.SigmaEncEndiannessMapImpl;
import com.intel.bkp.command.maps.SigmaM2EndiannessMapImpl;
import com.intel.bkp.command.maps.SpdmDmtfMeasurementHeaderEndiannessMapImpl;
import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.endianness.IStructureType;
import com.intel.bkp.core.interfaces.IEndiannessMap;
import lombok.RequiredArgsConstructor;

import java.util.function.Function;

@RequiredArgsConstructor
public enum StructureType implements IStructureType {
    SIGMA_M2(SigmaM2EndiannessMapImpl::new),
    SIGMA_ENC_RESP(SigmaEncEndiannessMapImpl::new),
    CERTIFICATE_RESP(CertificateResponseEndiannessMapImpl::new),
    CREATE_ATTESTATION_SUBKEY_RSP(CreateSubKeyRspEndiannessMapImpl::new),
    GET_MEASUREMENT_RSP(GetMeasurementRspEndiannessMapImpl::new),
    SPDM_DMTF_MEASUREMENT_HEADER(SpdmDmtfMeasurementHeaderEndiannessMapImpl::new);

    private final Function<EndiannessActor, IEndiannessMap> getEndiannessMap;

    @Override
    public IEndiannessMap getEndiannessMap(EndiannessActor actor) {
        return getEndiannessMap.apply(actor);
    }
}
