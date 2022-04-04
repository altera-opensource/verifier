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

import com.intel.bkp.verifier.exceptions.CommandFailedException;
import com.intel.bkp.verifier.exceptions.UnknownCommandException;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.sender.GetCertificateMessageSender;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.core.command.model.CertificateRequestType.FIRMWARE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GetDeviceAttestationComponentTest {

    private static final String REF_MEASUREMENT = "abcd";
    private static final byte[] DEVICE_ID = new byte[8];

    @Mock
    private AppContext appContext;

    @Mock
    private CommandLayer commandLayer;

    @Mock
    private TransportLayer transportLayer;

    @Mock
    private GetCertificateMessageSender getCertificateMessageSender;

    @Mock
    private S10AttestationComponent s10AttestationComponent;

    @Mock
    private DiceAttestationComponent diceAttestationComponent;

    @InjectMocks
    private GetDeviceAttestationComponent sut;

    @Test
    void perform_GetCertificatePasses_CallsFmDmAttestation() {
        // given
        mockAppContext();
        final byte[] response = new byte[] { 1, 2 };
        when(getCertificateMessageSender.send(any(), any(), eq(FIRMWARE))).thenReturn(response);

        // when
        sut.perform(appContext, REF_MEASUREMENT, DEVICE_ID);

        // then
        verify(diceAttestationComponent).perform(response, REF_MEASUREMENT, DEVICE_ID);
    }

    @Test
    void perform_GetCertificateFailsWithUnknownCommand_CallS10Attestation() {
        // given
        mockAppContext();
        doThrow(new UnknownCommandException("test", 1, 2, 3))
            .when(getCertificateMessageSender).send(any(), any(), any());

        // when
        sut.perform(appContext, REF_MEASUREMENT, DEVICE_ID);

        // then
        verify(s10AttestationComponent).perform(REF_MEASUREMENT, DEVICE_ID);
    }

    @Test
    void perform_GetCertificateFailsWithOtherError_Throws() {
        // given
        mockAppContext();
        doThrow(new CommandFailedException("test", 1, 2, 3))
            .when(getCertificateMessageSender).send(any(), any(), any());

        // when-then
        Assertions.assertThrows(CommandFailedException.class,
            () -> sut.perform(appContext, REF_MEASUREMENT, DEVICE_ID));

        // then
        verify(s10AttestationComponent, never()).perform(REF_MEASUREMENT, DEVICE_ID);
    }

    private void mockAppContext() {
        when(appContext.getTransportLayer()).thenReturn(transportLayer);
        when(appContext.getCommandLayer()).thenReturn(commandLayer);
    }
}
