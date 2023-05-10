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

package com.intel.bkp.verifier.service.spdm;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.verifier.exceptions.SpdmCommandFailedException;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.jna.LibSpdmLibraryWrapperImpl;
import com.intel.bkp.verifier.jna.LibSpdmLibraryWrapperImpl.LibSpdmLibraryWrapper;
import com.intel.bkp.verifier.jna.model.NativeSize;
import com.intel.bkp.verifier.jna.model.Uint8;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;

import static com.intel.bkp.crypto.constants.CryptoConstants.SHA384_SIG_LEN;
import static com.intel.bkp.utils.BitUtils.countSetBits;
import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.LIBSPDM_STATUS_SUCCESS;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
import static com.intel.bkp.verifier.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED;
import static com.intel.bkp.verifier.service.spdm.SpdmUtils.getBytes;
import static com.intel.bkp.verifier.service.spdm.SpdmUtils.throwOnError;

@Slf4j
@Getter(AccessLevel.PACKAGE)
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public class SpdmCaller {

    private static SpdmCaller INSTANCE;

    private final LibSpdmLibraryWrapper jnaInterface;
    private final SpdmParametersSetter spdmParametersSetter;

    private Pointer spdmContext;
    private Pointer scratchBuffer;

    private boolean connectionInitialized = false;

    public static synchronized SpdmCaller getInstance() {
        if (INSTANCE == null) {
            try {
                INSTANCE = new SpdmCaller(LibSpdmLibraryWrapperImpl.getInstance(), new SpdmParametersSetter());
                INSTANCE.initializeSpdmContext();
            } catch (UnsatisfiedLinkError e) {
                throw new VerifierRuntimeException("Failed to link SPDM Wrapper library.", e);
            }
        }
        return INSTANCE;
    }

    public String getVersion() throws SpdmCommandFailedException {
        log.debug("Sending SPDM GET_VERSION ...");

        final Long initGetVersionStatus = jnaInterface.libspdm_init_connection_w(spdmContext, true);
        log.debug("VERSION status: 0x{}", toHex(initGetVersionStatus));

        throwOnError(initGetVersionStatus);

        final ByteBuffer buffer = ByteBuffer.allocate(Byte.BYTES);
        jnaInterface.libspdm_get_version_w(spdmContext, buffer);

        return toHex(buffer.get());
    }

    public SpdmGetDigestResult getDigest() throws SpdmCommandFailedException {
        initializeConnection();

        log.debug("Sending SPDM GET_DIGESTS ...");

        final Pointer digestBuffer = new Memory(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);
        final Pointer slotMask = new Memory(Byte.BYTES);

        final Long statusDigest = jnaInterface.libspdm_get_digest_w(spdmContext, slotMask, digestBuffer);
        log.debug("DIGESTS status: 0x{}", toHex(statusDigest));

        throwOnError(statusDigest);

        final int hashAlgSize = CryptoConstants.SHA384_LEN;
        final byte[] slotMaskBytes = getBytes(slotMask, Byte.BYTES);
        return new SpdmGetDigestResult(slotMaskBytes,
            getBytes(digestBuffer, countSetBits(slotMaskBytes) * hashAlgSize), hashAlgSize);
    }

    public String getCerts(int slotId) throws SpdmCommandFailedException {
        initializeConnection();

        log.debug("Sending SPDM GET_CERTIFICATE ...");

        final Pointer certChain = new Memory(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);
        final Pointer certChainSize = new Memory(Long.BYTES);
        certChainSize.setLong(0, LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);

        final Long statusCert = jnaInterface.libspdm_get_certificate_w(spdmContext,
            new Uint8(slotId), certChainSize, certChain);
        log.debug("CERTIFICATE status: 0x{}", toHex(statusCert));

        throwOnError(statusCert);

        final byte[] certChainArray = getBytes(certChain, certChainSize);

        final String chain = toHex(certChainArray);
        log.debug("CERTIFICATE: {}", chain);

        return chain;
    }

    public String getMeasurements(int slotId) throws SpdmCommandFailedException {
        initializeConnection();

        log.debug("Sending SPDM GET_MEASUREMENTS ...");

        final Memory measurementRecord = new Memory(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);
        final Memory signature = new Memory(SHA384_SIG_LEN);
        final Pointer measurementRecordLength = new Memory(Integer.BYTES);
        measurementRecordLength.setInt(0, LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);

        final Long status = jnaInterface.libspdm_get_measurement_w(spdmContext, measurementRecordLength,
            measurementRecord, new Uint8(slotId), getRequestAttributes(), signature);
        log.debug("MEASUREMENTS status: 0x{}", toHex(status));

        throwOnError(status);

        final byte[] measurementsArray = getBytes(measurementRecord, measurementRecordLength);

        final String measurements = toHex(measurementsArray);
        log.debug("MEASUREMENTS: {}", measurements);

        return measurements;
    }

    private void initializeSpdmContext() {
        log.debug("Initializing SPDM context.");

        registerCallbacks();

        final long spdmContextSize = jnaInterface.libspdm_get_context_size_w().longValue();
        spdmContext = new Memory(spdmContextSize);

        final Long status = jnaInterface.libspdm_prepare_context_w(spdmContext);

        log.debug("Initialize context status: 0x{}", toHex(status));

        if (LIBSPDM_STATUS_SUCCESS != status) {
            throw new VerifierRuntimeException("Failed to initialize SPDM context.");
        }

        final NativeSize scratchBufferSize = jnaInterface.libspdm_get_sizeof_required_scratch_buffer_w(spdmContext);
        scratchBuffer = new Memory(scratchBufferSize.longValue());
        jnaInterface.libspdm_set_scratch_buffer_w(spdmContext, scratchBuffer, scratchBufferSize);

        spdmParametersSetter.setLibspdmParameters(spdmContext);
    }

    private void initializeConnection() throws SpdmCommandFailedException {
        if (!isConnectionInitialized()) {
            log.debug("Initializing SPDM connection.");

            final Long status = jnaInterface.libspdm_init_connection_w(spdmContext, false);
            log.debug("Init connection status: 0x{}", toHex(status));

            throwOnError(status);

            connectionInitialized = true;
        }
    }

    private void registerCallbacks() {
        jnaInterface.register_printf_callback(SpdmCallbacks::printfCallback);
        jnaInterface.register_mctp_encode_callback(SpdmCallbacks::mctpEncode);
        jnaInterface.register_mctp_decode_callback(SpdmCallbacks::mctpDecode);
        jnaInterface.register_spdm_device_send_message_callback(SpdmCallbacks::spdmDeviceSendMessage);
        jnaInterface.register_spdm_device_receive_message_callback(SpdmCallbacks::spdmDeviceReceiveMessage);
        jnaInterface.register_libspdm_transport_mctp_get_header_size_cust_callback(SpdmCallbacks::mctpGetHeaderSize);
        jnaInterface.register_spdm_device_acquire_sender_buffer(SpdmCallbacks::spdmDeviceAcquireSenderBuffer);
        jnaInterface.register_spdm_device_release_sender_buffer(SpdmCallbacks::spdmDeviceReleaseSenderBuffer);
        jnaInterface.register_spdm_device_acquire_receiver_buffer(SpdmCallbacks::spdmDeviceAcquireReceiverBuffer);
        jnaInterface.register_spdm_device_release_receiver_buffer(SpdmCallbacks::spdmDeviceReleaseReceiverBuffer);
    }

    private Uint8 getRequestAttributes() {
        final AppContext appContext = AppContext.instance();
        final boolean libSpdmMeasurementsRequestSignature =
            appContext.getLibConfig().getLibSpdmParams().isMeasurementsRequestSignature();

        if (libSpdmMeasurementsRequestSignature) {
            log.info("Verifying signature over measurements.");
            return new Uint8(SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE
                | SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED);
        } else {
            log.info("Skipping signature verification over measurements.");
            return new Uint8(SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED);
        }
    }
}
