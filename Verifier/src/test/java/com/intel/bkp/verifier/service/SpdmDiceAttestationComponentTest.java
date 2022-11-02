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

package com.intel.bkp.verifier.service;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoAggregator;
import com.intel.bkp.verifier.exceptions.SpdmCommandFailedException;
import com.intel.bkp.verifier.exceptions.VerifierRuntimeException;
import com.intel.bkp.verifier.interfaces.IDeviceMeasurementsProvider;
import com.intel.bkp.verifier.service.certificate.SpdmDiceChainService;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import com.intel.bkp.verifier.service.measurements.SpdmDeviceMeasurementsRequest;
import com.intel.bkp.verifier.service.sender.SpdmGetCertificateMessageSender;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SpdmDiceAttestationComponentTest {

    public static final byte[] CERT_CHAIN_FROM_DEVICE = {1, 2, 3, 4};
    public static final byte[] DEVICE_ID = {1, 2};
    public static final String REF_MEASUREMENT = "aabbccdd";
    public static final List<TcbInfo> TCB_INFOS_FROM_CHAIN = List.of(new TcbInfo());
    public static final List<TcbInfo> TCB_INFOS_FROM_MEASUREMENTS = List.of(new TcbInfo(), new TcbInfo());
    @Mock
    private IDeviceMeasurementsProvider<SpdmDeviceMeasurementsRequest> deviceMeasurementsProvider;
    @Mock
    private EvidenceVerifier evidenceVerifier;
    @Mock
    private TcbInfoAggregator tcbInfoAggregator;
    @Mock
    private SpdmDiceChainService spdmDiceChainService;
    @Mock
    private SpdmGetCertificateMessageSender spdmGetCertificateMessageSender;

    @InjectMocks
    private SpdmDiceAttestationComponent sut;

    @Test
    void perform_Success() {
        // given
        when(spdmGetCertificateMessageSender.send()).thenReturn(CERT_CHAIN_FROM_DEVICE);
        when(spdmDiceChainService.getTcbInfos()).thenReturn(TCB_INFOS_FROM_CHAIN);
        when(deviceMeasurementsProvider.getMeasurementsFromDevice(any())).thenReturn(TCB_INFOS_FROM_MEASUREMENTS);

        // when
        sut.perform(REF_MEASUREMENT, DEVICE_ID);

        // then
        verify(spdmDiceChainService).fetchAndVerifyDiceChains(DEVICE_ID, CERT_CHAIN_FROM_DEVICE);
        verify(tcbInfoAggregator).add(TCB_INFOS_FROM_CHAIN);
        verify(tcbInfoAggregator).add(TCB_INFOS_FROM_MEASUREMENTS);
        verify(evidenceVerifier).verify(tcbInfoAggregator, REF_MEASUREMENT);
    }

    @Test
    void perform_getCertChainFails_IgnoreFor223() {
        // given
        when(spdmGetCertificateMessageSender.send()).thenThrow(new SpdmCommandFailedException(1L));
        when(deviceMeasurementsProvider.getMeasurementsFromDevice(any())).thenReturn(TCB_INFOS_FROM_MEASUREMENTS);

        // when
        sut.perform(REF_MEASUREMENT, DEVICE_ID);

        // then
        verify(spdmDiceChainService, never()).fetchAndVerifyDiceChains(any(), any());
        verify(tcbInfoAggregator, never()).add(TCB_INFOS_FROM_CHAIN);
        verify(tcbInfoAggregator).add(TCB_INFOS_FROM_MEASUREMENTS);
        verify(evidenceVerifier).verify(tcbInfoAggregator, REF_MEASUREMENT);
    }

    @Test
    void perform_certFetchingFails_ThrowsException() {
        // given
        final String expectedExceptionMessage = "Failed to verify DICE certificate chain.";
        when(spdmGetCertificateMessageSender.send()).thenReturn(CERT_CHAIN_FROM_DEVICE);
        doThrow(new RuntimeException("TEST")).when(spdmDiceChainService)
            .fetchAndVerifyDiceChains(DEVICE_ID, CERT_CHAIN_FROM_DEVICE);

        // when-then
        final VerifierRuntimeException exception =
            assertThrows(VerifierRuntimeException.class, () -> sut.perform(REF_MEASUREMENT, DEVICE_ID));

        // then
        assertEquals(expectedExceptionMessage, exception.getMessage());
        verify(tcbInfoAggregator, never()).add(any());
        verify(evidenceVerifier, never()).verify(any(), anyString());
    }

    @Test
    void perform_GetMeasurementsFailedThrowsSpdmCommandFailedException_Rethrows() {
        // given
        final SpdmCommandFailedException expectedException = new SpdmCommandFailedException(1L);
        doThrow(expectedException).when(deviceMeasurementsProvider).getMeasurementsFromDevice(any());

        // when
        final SpdmCommandFailedException actualException =
            assertThrows(SpdmCommandFailedException.class, () -> sut.perform(REF_MEASUREMENT, DEVICE_ID));

        // then
        assertSame(expectedException, actualException);
        verify(tcbInfoAggregator, never()).add(any());
        verify(evidenceVerifier, never()).verify(any(), anyString());
    }

    @Test
    void perform_GetMeasurementsThrowsOtherException_ThrowsVerifierRuntimeException() {
        // given
        final String expectedExceptionMessage = "Failed to retrieve measurements from device.";
        doThrow(new RuntimeException("TEST")).when(deviceMeasurementsProvider).getMeasurementsFromDevice(any());

        // when
        final VerifierRuntimeException exception =
            assertThrows(VerifierRuntimeException.class, () -> sut.perform(REF_MEASUREMENT, DEVICE_ID));

        // then
        assertEquals(expectedExceptionMessage, exception.getMessage());
        verify(tcbInfoAggregator, never()).add(any());
        verify(evidenceVerifier, never()).verify(any(), anyString());
    }
}
