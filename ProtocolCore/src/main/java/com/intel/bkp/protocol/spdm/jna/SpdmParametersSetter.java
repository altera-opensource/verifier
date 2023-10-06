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

package com.intel.bkp.protocol.spdm.jna;

import com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataLocation;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataParameter;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmDataType;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmLibraryWrapper;
import com.intel.bkp.protocol.spdm.jna.model.SpdmConstants;
import com.intel.bkp.protocol.spdm.jna.model.SpdmParametersProvider;
import com.intel.bkp.protocol.spdm.jna.model.Uint32;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;
import com.sun.jna.Pointer;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class SpdmParametersSetter {

    final LibSpdmDataParameter.ByReference parameter = new LibSpdmDataParameter.ByReference();

    public void setLibspdmParameters(LibSpdmLibraryWrapper jnaInterface, Pointer context,
                                     SpdmParametersProvider provider) {
        parameter.setLocation(LibSpdmDataLocation.LIBSPDM_DATA_LOCATION_LOCAL);

        final Uint8 libSpdmCtExponentData = new Uint8(provider.ctExponent());
        jnaInterface.libspdm_set_data_w8(context, LibSpdmDataType.LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, parameter,
                libSpdmCtExponentData, Uint8.NATIVE_SIZE);

        final Uint8 libSpdmMeasurementSpecData =
            new Uint8(SpdmConstants.SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF);
        jnaInterface.libspdm_set_data_w8(context, LibSpdmDataType.LIBSPDM_DATA_MEASUREMENT_SPEC, parameter,
                libSpdmMeasurementSpecData, Uint8.NATIVE_SIZE);


        final Uint32 libSpdmBaseAsymAlgoData =
            new Uint32(SpdmConstants.SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384);
        jnaInterface.libspdm_set_data_w32(context, LibSpdmDataType.LIBSPDM_DATA_BASE_ASYM_ALGO, parameter,
                libSpdmBaseAsymAlgoData, Uint32.NATIVE_SIZE);

        final Uint32 libSpdmBaseHashAlgoData = new Uint32(SpdmConstants.SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384);
        jnaInterface.libspdm_set_data_w32(context, LibSpdmDataType.LIBSPDM_DATA_BASE_HASH_ALGO, parameter,
                libSpdmBaseHashAlgoData, Uint32.NATIVE_SIZE);
    }
}
