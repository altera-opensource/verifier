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

package com.intel.bkp.protocol.spdm.jna.model;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

import java.nio.ByteBuffer;

public interface LibSpdmLibraryWrapper extends Library {

    static LibSpdmLibraryWrapper getInstance(String wrapperLibraryPath) {
        return Native.load(wrapperLibraryPath, LibSpdmLibraryWrapper.class);
    }

    void set_callbacks(SessionCallbacks callbacks);

    void libspdm_get_version_w(Pointer spdmContext, ByteBuffer version);

    NativeSize libspdm_get_context_size_w();

    Long libspdm_prepare_context_w(Pointer spdmContextP, Uint32 bufferSize);

    NativeSize libspdm_get_sizeof_required_scratch_buffer_w(Pointer spdmContextP);

    void libspdm_set_scratch_buffer_w(Pointer spdmContextP, Pointer scratchBuffer, NativeSize scratchBufferSize);

    Long libspdm_init_connection_w(Pointer spdmContextP, boolean versionOnly);

    Long libspdm_set_data_w8(Pointer spdmContext, int dataType,
                             LibSpdmDataParameter.ByReference parameter,
                             Uint8 data, NativeSize dataSize);

    Long libspdm_set_data_w32(Pointer spdmContext, int dataType,
                              LibSpdmDataParameter.ByReference parameter,
                              Uint32 data, NativeSize dataSize);

    Long libspdm_get_digest_w(Pointer spdmContext, Pointer slotMask, Pointer totalDigestBuffer);

    Long libspdm_get_certificate_w(Pointer spdmContext, Uint8 slotId, Pointer certChainSize, Pointer certChain);

    Long libspdm_get_measurement_w(Pointer spdmContext, Pointer measurementRecordLength, Pointer measurementRecord,
                                   Uint8 slotIdMeasurements, Uint8 requestAttribute, Pointer signature);

    Long libspdm_set_certificate_w(Pointer spdmContext, Pointer sessionId, Uint8 slotId,
                                   Pointer certChain, NativeSize certChainSize);

}
