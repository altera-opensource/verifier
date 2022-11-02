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

package com.intel.bkp.verifier.jna;

import com.intel.bkp.verifier.jna.model.LibSpdmDataParameter;
import com.intel.bkp.verifier.jna.model.LibSpdmReturn;
import com.intel.bkp.verifier.jna.model.MctpDecodeCallback;
import com.intel.bkp.verifier.jna.model.MctpEncodeCallback;
import com.intel.bkp.verifier.jna.model.MctpGetHeaderSizeCallback;
import com.intel.bkp.verifier.jna.model.NativeSize;
import com.intel.bkp.verifier.jna.model.PrintCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceAcquireReceiverBufferCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceAcquireSenderBufferCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceReceiveMessageCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceReleaseReceiverBufferCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceReleaseSenderBufferCallback;
import com.intel.bkp.verifier.jna.model.SpdmDeviceSendMessageCallback;
import com.intel.bkp.verifier.jna.model.Uint32;
import com.intel.bkp.verifier.jna.model.Uint8;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.nio.ByteBuffer;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class LibSpdmLibraryWrapperImpl {

    private static LibSpdmLibraryWrapper INSTANCE = null;

    public static LibSpdmLibraryWrapper getInstance() {
        if (INSTANCE == null) {
            INSTANCE = LibSpdmLibraryWrapper.getInstance();
        }
        return INSTANCE;
    }

    public interface LibSpdmLibraryWrapper extends Library {

        private static LibSpdmLibraryWrapper getInstance() {
            final AppContext appContext = AppContext.instance();
            return Native.load(
                appContext.getLibConfig().getLibSpdmParams().getWrapperLibraryPath(),
                LibSpdmLibraryWrapper.class);
        }

        void register_printf_callback(PrintCallback callback);

        LibSpdmReturn register_mctp_encode_callback(MctpEncodeCallback callback);

        LibSpdmReturn register_mctp_decode_callback(MctpDecodeCallback callback);

        LibSpdmReturn register_spdm_device_send_message_callback(SpdmDeviceSendMessageCallback callback);

        LibSpdmReturn register_spdm_device_receive_message_callback(SpdmDeviceReceiveMessageCallback callback);

        void register_libspdm_transport_mctp_get_header_size_cust_callback(MctpGetHeaderSizeCallback callback);

        void register_spdm_device_acquire_sender_buffer(SpdmDeviceAcquireSenderBufferCallback callback);

        void register_spdm_device_release_sender_buffer(SpdmDeviceReleaseSenderBufferCallback callback);

        void register_spdm_device_acquire_receiver_buffer(SpdmDeviceAcquireReceiverBufferCallback callback);

        void register_spdm_device_release_receiver_buffer(SpdmDeviceReleaseReceiverBufferCallback callback);

        void libspdm_get_version_w(Pointer spdmContext, ByteBuffer version);

        NativeSize libspdm_get_context_size_w();

        Long libspdm_prepare_context_w(Pointer spdmContextP);

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
    }
}
