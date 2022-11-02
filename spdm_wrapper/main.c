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

#include "main.h"

printf_callback printfCallback = NULL;
mctp_encode_callback mctpEncodeCallback = NULL;
mctp_decode_callback mctpDecodeCallback = NULL;
libspdm_transport_mctp_get_header_size_cust_callback mctpGetHeaderSizeCustCallback = NULL;

spdm_device_send_message_callback spdmDeviceSendMessageCallback = NULL;
spdm_device_receive_message_callback spdmDeviceReceiveMessageCallback = NULL;

spdm_device_acquire_sender_buffer_callback spdmDeviceAcquireSenderBufferCallback = NULL;
spdm_device_release_sender_buffer_callback spdmDeviceReleaseSenderBufferCallback = NULL;
spdm_device_acquire_receiver_buffer_callback spdmDeviceAcquireReceiverBufferCallback = NULL;
spdm_device_release_receiver_buffer_callback spdmDeviceReleaseReceiverBufferCallback = NULL;

void register_printf_callback(const printf_callback callback) {
    printfCallback = callback;
}

void register_mctp_encode_callback(const mctp_encode_callback callback) {
    mctpEncodeCallback = callback;
}

void register_mctp_decode_callback(const mctp_decode_callback callback) {
    mctpDecodeCallback = callback;
}

void register_spdm_device_send_message_callback(const spdm_device_send_message_callback callback) {
    spdmDeviceSendMessageCallback = callback;
}

void register_spdm_device_receive_message_callback(const spdm_device_receive_message_callback callback) {
    spdmDeviceReceiveMessageCallback = callback;
}

void register_libspdm_transport_mctp_get_header_size_cust_callback(
        const libspdm_transport_mctp_get_header_size_cust_callback callback) {
    mctpGetHeaderSizeCustCallback = callback;
}

void register_spdm_device_acquire_sender_buffer(const spdm_device_acquire_sender_buffer_callback callback) {
    spdmDeviceAcquireSenderBufferCallback = callback;
}

void register_spdm_device_release_sender_buffer(const spdm_device_release_sender_buffer_callback callback) {
    spdmDeviceReleaseSenderBufferCallback = callback;
}

void register_spdm_device_acquire_receiver_buffer(const spdm_device_acquire_receiver_buffer_callback callback) {
    spdmDeviceAcquireReceiverBufferCallback = callback;
}

void register_spdm_device_release_receiver_buffer(const spdm_device_release_receiver_buffer_callback callback) {
    spdmDeviceReleaseReceiverBufferCallback = callback;
}

bool verify_spdm_cert_chain_func(
        void *spdm_context, uint8_t slot_id,
        size_t cert_chain_size, const void *cert_chain,
        const void **trust_anchor,
        size_t *trust_anchor_size) {
    return true;
}

void libspdm_get_version_w(void *spdm_context, uint8_t *version_p) {
    libspdm_context_t *spdm_context_p = (libspdm_context_t *) spdm_context;
    *version_p = libspdm_get_connection_version(spdm_context_p);
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

libspdm_return_t libspdm_prepare_context_w(void *spdm_context) {
    libspdm_return_t status = libspdm_init_context(spdm_context);

    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return status;
    }

    libspdm_register_verify_spdm_cert_chain_func(spdm_context, verify_spdm_cert_chain_func);

    libspdm_register_device_buffer_func(spdm_context,
                                        spdmDeviceAcquireSenderBufferCallback,
                                        spdmDeviceReleaseSenderBufferCallback,
                                        spdmDeviceAcquireReceiverBufferCallback,
                                        spdmDeviceReleaseReceiverBufferCallback);

    libspdm_register_device_io_func(spdm_context, spdmDeviceSendMessageCallback,
                                    spdmDeviceReceiveMessageCallback);

    libspdm_register_transport_layer_func(
            spdm_context, mctpEncodeCallback, mctpDecodeCallback, mctpGetHeaderSizeCustCallback);

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
    return libspdm_init_connection(spdm_context, get_version_only);
}

libspdm_return_t libspdm_get_digest_w(void *spdm_context, uint8_t *slot_mask,
                                      void *total_digest_buffer) {
    return libspdm_get_digest(spdm_context, slot_mask, total_digest_buffer);
}

libspdm_return_t libspdm_get_certificate_w(void *spdm_context, uint8_t slot_id,
                                           size_t *cert_chain_size,
                                           void *cert_chain) {
    return libspdm_get_certificate(spdm_context, slot_id, cert_chain_size, cert_chain);
}

libspdm_return_t libspdm_get_measurement_w(void *spdm_context,
                                           uint32_t *measurement_record_length,
                                           void *measurement_record,
                                           uint8_t slot_id_measurements,
                                           uint8_t request_attribute,
                                           void *signature) {
    uint8_t number_of_block;
    return libspdm_get_measurement(
            spdm_context, NULL, request_attribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
            slot_id_measurements & 0xF, NULL, &number_of_block,
            measurement_record_length, measurement_record);
}
