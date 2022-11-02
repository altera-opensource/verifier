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

#ifndef SPDM_WRAPPER_MAIN_H
#define SPDM_WRAPPER_MAIN_H

#include <stdlib.h>

#include "internal/libspdm_common_lib.h"
#include "library/spdm_requester_lib.h"

#if PORT == WINDOWS
#define PGM_PLUGIN_DLLEXPORT __declspec (dllexport)
#else
#if __GNUC__ == 4
        #if __GNUC_MINOR__ >= 5 && __GNUC_MINOR__ <= 8
            #define PGM_PLUGIN_DLLEXPORT __attribute__((visibility("default")))
        #else
            #define PGM_PLUGIN_DLLEXPORT  __attribute__((visibility("protected")))
        #endif
    #elif __GNUC__ >= 5
        #define PGM_PLUGIN_DLLEXPORT __attribute__((visibility("default")))
    #else
        #define PGM_PLUGIN_DLLEXPORT UNKNOWN
    #endif
#endif

typedef void (*printf_callback)
        (const char *message);

typedef libspdm_return_t (*mctp_encode_callback)
        (void *spdm_context, const uint32_t *session_id, bool is_app_message,
         bool is_requester, size_t message_size, void *message,
         size_t *transport_message_size, void **transport_message);

typedef libspdm_return_t (*mctp_decode_callback)
        (void *spdm_context, uint32_t **session_id,
         bool *is_app_message, bool is_requester,
         size_t transport_message_size, void *transport_message,
         size_t *message_size, void **message);

typedef libspdm_return_t (*spdm_device_send_message_callback)
        (void *spdm_context, size_t request_size, const void *request, uint64_t timeout);

typedef libspdm_return_t (*spdm_device_receive_message_callback)
        (void *spdm_context, size_t *response_size, void **response, uint64_t timeout);

typedef uint32_t (*libspdm_transport_mctp_get_header_size_cust_callback)
        (void *spdm_context);

typedef libspdm_return_t (*spdm_device_acquire_sender_buffer_callback)
        (void *context, size_t *max_msg_size, void **msg_buf_ptr);

typedef void (*spdm_device_release_sender_buffer_callback)
        (void *context, const void *msg_buf_ptr);

typedef libspdm_return_t (*spdm_device_acquire_receiver_buffer_callback)
        (void *context, size_t *max_msg_size, void **msg_buf_ptr);

typedef void (*spdm_device_release_receiver_buffer_callback)
        (void *context, const void *msg_buf_ptr);

PGM_PLUGIN_DLLEXPORT void
register_printf_callback(printf_callback callback);

PGM_PLUGIN_DLLEXPORT void
register_mctp_encode_callback(mctp_encode_callback callback);

PGM_PLUGIN_DLLEXPORT void
register_mctp_decode_callback(mctp_decode_callback callback);

PGM_PLUGIN_DLLEXPORT void
register_spdm_device_send_message_callback(spdm_device_send_message_callback callback);

PGM_PLUGIN_DLLEXPORT void
register_spdm_device_receive_message_callback(spdm_device_receive_message_callback callback);

PGM_PLUGIN_DLLEXPORT void
register_libspdm_transport_mctp_get_header_size_cust_callback(
        libspdm_transport_mctp_get_header_size_cust_callback callback);

PGM_PLUGIN_DLLEXPORT void
register_spdm_device_acquire_sender_buffer(spdm_device_acquire_sender_buffer_callback callback);

PGM_PLUGIN_DLLEXPORT void
register_spdm_device_release_sender_buffer(spdm_device_release_sender_buffer_callback callback);

PGM_PLUGIN_DLLEXPORT void
register_spdm_device_acquire_receiver_buffer(spdm_device_acquire_receiver_buffer_callback callback);

PGM_PLUGIN_DLLEXPORT void
register_spdm_device_release_receiver_buffer(spdm_device_release_receiver_buffer_callback callback);

PGM_PLUGIN_DLLEXPORT void
libspdm_get_version_w(void *spdm_context_p,
                      uint8_t *version_p);

PGM_PLUGIN_DLLEXPORT libspdm_return_t
libspdm_set_data_w8(void *spdm_context,
                   libspdm_data_type_t data_type,
                   const libspdm_data_parameter_t *parameter,
                   uint8_t data,
                   size_t data_size);

PGM_PLUGIN_DLLEXPORT libspdm_return_t
libspdm_set_data_w32(void *spdm_context,
                   libspdm_data_type_t data_type,
                   const libspdm_data_parameter_t *parameter,
                   uint32_t data,
                   size_t data_size);

PGM_PLUGIN_DLLEXPORT size_t
libspdm_get_context_size_w();

PGM_PLUGIN_DLLEXPORT libspdm_return_t
libspdm_prepare_context_w(void *spdm_context);

PGM_PLUGIN_DLLEXPORT size_t
libspdm_get_sizeof_required_scratch_buffer_w(void *spdm_context);

PGM_PLUGIN_DLLEXPORT void
libspdm_set_scratch_buffer_w(void *spdm_context,
                          void *scratch_buffer,
                          size_t scratch_buffer_size);

PGM_PLUGIN_DLLEXPORT libspdm_return_t
libspdm_init_connection_w(void *spdm_context,
                          bool get_version_only);

PGM_PLUGIN_DLLEXPORT libspdm_return_t
libspdm_get_digest_w(void *spdm_context,
                     uint8_t *slot_mask,
                     void *total_digest_buffer);

PGM_PLUGIN_DLLEXPORT libspdm_return_t
libspdm_get_certificate_w(void *spdm_context,
                          uint8_t slot_id,
                          size_t *cert_chain_size,
                          void *cert_chain);

PGM_PLUGIN_DLLEXPORT libspdm_return_t
libspdm_get_measurement_w(void *spdm_context,
                          uint32_t *measurement_record_length,
                          void *measurement_record,
                          uint8_t slot_id_measurements,
                          uint8_t request_attribute,
                          void *signature);

#endif //SPDM_WRAPPER_MAIN_H
