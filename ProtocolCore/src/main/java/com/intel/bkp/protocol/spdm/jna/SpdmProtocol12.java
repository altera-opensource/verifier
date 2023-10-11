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

import com.intel.bkp.protocol.spdm.exceptions.SpdmCommandFailedException;
import com.intel.bkp.protocol.spdm.exceptions.SpdmRuntimeException;
import com.intel.bkp.protocol.spdm.jna.model.LibSpdmLibraryWrapper;
import com.intel.bkp.protocol.spdm.jna.model.MessageLogger;
import com.intel.bkp.protocol.spdm.jna.model.MessageSender;
import com.intel.bkp.protocol.spdm.jna.model.NativeSize;
import com.intel.bkp.protocol.spdm.jna.model.SessionCallbacks;
import com.intel.bkp.protocol.spdm.jna.model.SpdmContext;
import com.intel.bkp.protocol.spdm.jna.model.SpdmGetDigestResult;
import com.intel.bkp.protocol.spdm.jna.model.SpdmParametersProvider;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import com.intel.bkp.protocol.spdm.jna.model.Uint32;
import com.intel.bkp.protocol.spdm.jna.model.Uint8;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;

import static com.intel.bkp.protocol.spdm.jna.SpdmUtils.getBytes;
import static com.intel.bkp.protocol.spdm.jna.SpdmUtils.throwOnError;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.LIBSPDM_STATUS_SUCCESS;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
import static com.intel.bkp.protocol.spdm.jna.model.SpdmConstants.SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED;
import static com.intel.bkp.utils.BitUtils.countSetBits;
import static com.intel.bkp.utils.HexConverter.toFormattedHex;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
public abstract class SpdmProtocol12 implements SpdmProtocol {

    private static final int SHA384_LEN = 48;
    private static final int SHA384_SIG_LEN = 2 * SHA384_LEN;

    private final SpdmParametersSetter spdmParametersSetter = new SpdmParametersSetter();
    @Getter
    private final SessionCallbacks.ByReference callbacks = new SessionCallbacks.ByReference();
    private final SpdmCallbacks spdmCallbacks;
    private final SpdmParametersProvider parametersProvider;

    private SpdmContext spdmContext;

    @Getter
    private boolean connectionInitialized = false;

    protected LibSpdmLibraryWrapper jnaInterface;

    protected abstract void initializeLibrary();

    protected abstract boolean isMeasurementsRequestSignature();

    protected SpdmProtocol12(MessageSender messageSender, MessageLogger messageLogger,
                             SpdmParametersProvider parametersProvider) {
        this.spdmCallbacks = new SpdmCallbacks(messageSender, messageLogger);
        this.parametersProvider = parametersProvider;
    }

    @Override
    public String getVersion() throws SpdmCommandFailedException {
        initializeLibrary();
        initializeSpdmContext();
        return getVersionInternal();
    }

    @Override
    public SpdmGetDigestResult getDigest() throws SpdmCommandFailedException {
        initializeLibrary();
        initializeSpdmContext();
        initializeConnection();
        return getDigestInternal();
    }

    @Override
    public String getCerts(int slotId) throws SpdmCommandFailedException {
        initializeLibrary();
        initializeSpdmContext();
        initializeConnection();
        return getCertsInternal(slotId);
    }

    @Override
    public String getMeasurements(int slotId) throws SpdmCommandFailedException {
        initializeLibrary();
        initializeSpdmContext();
        initializeConnection();
        return getMeasurementsInternal(slotId);
    }

    void initializeSpdmContext() {
        if (spdmContext != null) {
            log.debug("SPDM context already initialized.");
            return;
        }

        log.debug("Initializing SPDM context.");

        registerCallbacks();

        final long spdmContextSize = jnaInterface.libspdm_get_context_size_w().longValue();
        final Pointer spdmContext = new Memory(spdmContextSize);

        final Long status = jnaInterface.libspdm_prepare_context_w(spdmContext,
            new Uint32(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE));

        log.debug("Initialize context status: {}", toFormattedHex(status));

        if (LIBSPDM_STATUS_SUCCESS != status) {
            throw new SpdmRuntimeException("Failed to initialize SPDM context.");
        }

        final NativeSize scratchBufferSize = jnaInterface.libspdm_get_sizeof_required_scratch_buffer_w(spdmContext);
        final Pointer scratchBuffer = new Memory(scratchBufferSize.longValue());
        jnaInterface.libspdm_set_scratch_buffer_w(spdmContext, scratchBuffer, scratchBufferSize);

        spdmParametersSetter.setLibspdmParameters(jnaInterface, spdmContext, parametersProvider);

        this.spdmContext = new SpdmContext(spdmContext, scratchBuffer);
    }

    private void initializeConnection() throws SpdmCommandFailedException {
        if (!isConnectionInitialized()) {
            log.debug("Initializing SPDM connection.");

            final Long status = jnaInterface.libspdm_init_connection_w(spdmContext.getContext(), false);
            log.debug("Init connection status: {}", toFormattedHex(status));

            throwOnError(status);

            connectionInitialized = true;
        }
    }

    private String getVersionInternal() throws SpdmCommandFailedException {
        log.debug("Sending SPDM GET_VERSION ...");

        final Long initGetVersionStatus = jnaInterface.libspdm_init_connection_w(spdmContext.getContext(), true);
        log.debug("VERSION status: {}", toFormattedHex(initGetVersionStatus));

        throwOnError(initGetVersionStatus);

        final ByteBuffer buffer = ByteBuffer.allocate(Byte.BYTES);
        jnaInterface.libspdm_get_version_w(spdmContext.getContext(), buffer);

        return toHex(buffer.get());
    }

    private SpdmGetDigestResult getDigestInternal() throws SpdmCommandFailedException {
        log.debug("Sending SPDM GET_DIGESTS ...");

        final Pointer digestBuffer = new Memory(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);
        final Pointer slotMask = new Memory(Byte.BYTES);

        final Long statusDigest = jnaInterface.libspdm_get_digest_w(spdmContext.getContext(), slotMask, digestBuffer);
        log.debug("DIGESTS status: {}", toFormattedHex(statusDigest));

        throwOnError(statusDigest);

        final int hashAlgSize = SHA384_LEN;
        final byte[] slotMaskBytes = getBytes(slotMask, Byte.BYTES);
        return new SpdmGetDigestResult(slotMaskBytes,
            getBytes(digestBuffer, countSetBits(slotMaskBytes) * hashAlgSize), hashAlgSize);
    }

    private String getCertsInternal(int slotId) throws SpdmCommandFailedException {
        log.debug("Sending SPDM GET_CERTIFICATE ...");

        final Pointer certChain = new Memory(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);
        final Pointer certChainSize = new Memory(Long.BYTES);
        certChainSize.setLong(0, LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);

        final Long statusCert = jnaInterface.libspdm_get_certificate_w(spdmContext.getContext(),
            new Uint8(slotId), certChainSize, certChain);
        log.debug("CERTIFICATE status: {}", toFormattedHex(statusCert));

        throwOnError(statusCert);

        final byte[] certChainArray = getBytes(certChain, certChainSize);

        final String chain = toHex(certChainArray);
        log.debug("CERTIFICATE: {}", chain);

        return chain;
    }

    private String getMeasurementsInternal(int slotId) throws SpdmCommandFailedException {
        log.debug("Sending SPDM GET_MEASUREMENTS ...");

        final Memory measurementRecord = new Memory(LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);
        final Memory signature = new Memory(SHA384_SIG_LEN);
        final Pointer measurementRecordLength = new Memory(Integer.BYTES);
        measurementRecordLength.setInt(0, LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE);

        final Long status = jnaInterface.libspdm_get_measurement_w(spdmContext.getContext(), measurementRecordLength,
            measurementRecord, new Uint8(slotId), getRequestAttributes(), signature);
        log.debug("MEASUREMENTS status: {}", toFormattedHex(status));

        throwOnError(status);

        final byte[] measurementsArray = getBytes(measurementRecord, measurementRecordLength);

        final String measurements = toHex(measurementsArray);
        log.debug("MEASUREMENTS: {}", measurements);

        return measurements;
    }

    private void registerCallbacks() {
        callbacks.setPrintCallback(spdmCallbacks::printCallback);

        callbacks.setMctpEncodeCallback(spdmCallbacks::mctpEncode);
        callbacks.setMctpDecodeCallback(spdmCallbacks::mctpDecode);

        callbacks.setSpdmDeviceSendMessageCallback(spdmCallbacks::spdmDeviceSendMessage);
        callbacks.setSpdmDeviceReceiveMessageCallback(spdmCallbacks::spdmDeviceReceiveMessage);

        callbacks.setSpdmDeviceAcquireSenderBufferCallback(spdmCallbacks::spdmDeviceAcquireSenderBuffer);
        callbacks.setSpdmDeviceReleaseSenderBufferCallback(spdmCallbacks::spdmDeviceReleaseSenderBuffer);

        callbacks.setSpdmDeviceAcquireReceiverBufferCallback(spdmCallbacks::spdmDeviceAcquireReceiverBuffer);
        callbacks.setSpdmDeviceReleaseReceiverBufferCallback(spdmCallbacks::spdmDeviceReleaseReceiverBuffer);

        jnaInterface.set_callbacks(callbacks);
    }

    protected Uint8 getRequestAttributes() {
        if (isMeasurementsRequestSignature()) {
            log.info("Verifying signature over measurements.");
            return new Uint8(SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE
                | SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED);
        } else {
            log.info("Skipping signature verification over measurements.");
            return new Uint8(SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED);
        }
    }
}
