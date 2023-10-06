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

#include "main.h"

session_callbacks_t *cb;

void set_callbacks(session_callbacks_t *callbacks) {
    cb = callbacks;
}

bool verify_spdm_cert_chain_func(
        void *spdm_context, uint8_t slot_id,
        size_t cert_chain_size, const void *cert_chain,
        const void **trust_anchor,
        size_t *trust_anchor_size) {
    return true;
}

void libspdm_get_version_w(void *spdm_context, uint8_t *version_p) {
    spdm_version_number_t spdm_version_number_entry;
    libspdm_data_parameter_t parameter;
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    size_t data_size = sizeof(spdm_version_number_entry);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                     &spdm_version_number_entry, &data_size);

    cb->printCallback("Called libspdm_get_version_w.");

    // We are only interested in [15:12] MajorVersion [11:8] MinorVersion part of VersionNumberEntry
    *version_p = spdm_version_number_entry >> SPDM_VERSION_NUMBER_SHIFT_BIT;
}

libspdm_return_t libspdm_set_data_w8(void *spdm_context,
                                     libspdm_data_type_t data_type,
                                     const libspdm_data_parameter_t *parameter, uint8_t data,
                                     size_t data_size) {
    return libspdm_set_data(spdm_context, data_type, parameter, &data, data_size);
}

libspdm_return_t libspdm_set_data_w32(void *spdm_context,
                                      libspdm_data_type_t data_type,
                                      const libspdm_data_parameter_t *parameter, uint32_t data,
                                      size_t data_size) {
    return libspdm_set_data(spdm_context, data_type, parameter, &data, data_size);
}

size_t libspdm_get_context_size_w() {
    return libspdm_get_context_size();
}

libspdm_return_t libspdm_prepare_context_w(void *spdm_context, uint32_t bufferSize) {
    uint32_t senderBufferSize = bufferSize;
    uint32_t receiverBufferSize = bufferSize;
    uint32_t maxSpdmMessageSize = bufferSize - MAILBOX_HEADER_SIZE;
    uint32_t transportHeaderSize = MAILBOX_HEADER_SIZE;
    uint32_t transportTailSize = 0;

    libspdm_return_t status = libspdm_init_context(spdm_context);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    libspdm_register_verify_spdm_cert_chain_func(spdm_context, verify_spdm_cert_chain_func);

    libspdm_register_device_buffer_func(spdm_context,
                                        senderBufferSize,
                                        receiverBufferSize,
                                        cb->spdmDeviceAcquireSenderBufferCallback,
                                        cb->spdmDeviceReleaseSenderBufferCallback,
                                        cb->spdmDeviceAcquireReceiverBufferCallback,
                                        cb->spdmDeviceReleaseReceiverBufferCallback);

    libspdm_register_device_io_func(spdm_context, cb->spdmDeviceSendMessageCallback,
                                    cb->spdmDeviceReceiveMessageCallback);

    libspdm_register_transport_layer_func(spdm_context,
                                          maxSpdmMessageSize,
                                          transportHeaderSize,
                                          transportTailSize,
                                          cb->mctpEncodeCallback,
                                          cb->mctpDecodeCallback);
    return LIBSPDM_STATUS_SUCCESS;
}

size_t libspdm_get_sizeof_required_scratch_buffer_w(void *spdm_context) {
    return libspdm_get_sizeof_required_scratch_buffer(spdm_context);
}

void libspdm_set_scratch_buffer_w(void *spdm_context,
                                  void *scratch_buffer,
                                  size_t scratch_buffer_size) {
    libspdm_set_scratch_buffer(spdm_context, scratch_buffer, scratch_buffer_size);
}

libspdm_return_t libspdm_init_connection_w(void *spdm_context,
                                           bool get_version_only) {
    cb->printCallback("Called libspdm_init_connection_w.");
    return libspdm_init_connection(spdm_context, get_version_only);
}

libspdm_return_t libspdm_get_digest_w(void *spdm_context, uint8_t *slot_mask,
                                      void *total_digest_buffer) {
    cb->printCallback("Called libspdm_get_digest_w.");
    return libspdm_get_digest(spdm_context, NULL, slot_mask, total_digest_buffer);
}

libspdm_return_t libspdm_get_certificate_w(void *spdm_context, uint8_t slot_id,
                                           size_t *cert_chain_size,
                                           void *cert_chain) {
    cb->printCallback("Called libspdm_get_certificate_w.");
    return libspdm_get_certificate(spdm_context, NULL, slot_id, cert_chain_size, cert_chain);
}

libspdm_return_t libspdm_get_measurement_w(void *spdm_context,
                                           uint32_t *measurement_record_length,
                                           void *measurement_record,
                                           uint8_t slot_id_measurements,
                                           uint8_t request_attribute,
                                           void *signature) {
    cb->printCallback("Called libspdm_get_measurement_w.");
    uint8_t number_of_block;
    return libspdm_get_measurement(
            spdm_context, NULL, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
            slot_id_measurements & 0xF, NULL, &number_of_block,
            measurement_record_length, measurement_record);
}

libspdm_return_t libspdm_set_certificate_w(void *spdm_context,
                                         const uint32_t *session_id, uint8_t slot_id,
                                         void *cert_chain, size_t cert_chain_size) {
    cb->printCallback("Called libspdm_set_certificate_w.");
    return libspdm_set_certificate(spdm_context, NULL, slot_id, cert_chain, cert_chain_size);
}
