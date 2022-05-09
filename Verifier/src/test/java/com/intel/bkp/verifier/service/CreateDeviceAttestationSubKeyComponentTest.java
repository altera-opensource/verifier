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

import com.intel.bkp.core.manufacturing.model.PufType;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.verifier.command.responses.subkey.CreateAttestationSubKeyResponseBuilder;
import com.intel.bkp.verifier.database.SQLiteHelper;
import com.intel.bkp.verifier.database.repository.S10CacheEntityService;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.certificate.S10AttestationRevocationService;
import com.intel.bkp.verifier.service.sender.CreateAttestationSubKeyMessageSender;
import com.intel.bkp.verifier.service.sender.TeardownMessageSender;
import com.intel.bkp.verifier.sigma.CreateAttestationSubKeyVerifier;
import com.intel.bkp.verifier.sigma.SigmaM2DeviceIdVerifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CreateDeviceAttestationSubKeyComponentTest {

    private static final String CONTEXT = "0102";
    private static final PufType PUF_TYPE = PufType.EFUSE;
    private static final byte[] DEVICE_ID = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    private static final byte[] SDM_SESSION_ID = { 0, 0, 0, 1 };

    @Mock
    private AppContext appContext;

    @Mock
    private SQLiteHelper sqLiteHelper;

    @Mock
    private PublicKey pufPubKey;

    @Mock
    private CommandLayer commandLayer;

    @Mock
    private TransportLayer transportLayer;

    @Mock
    private CreateAttestationSubKeyMessageSender createSubKeyMessageSender;

    @Mock
    private TeardownMessageSender teardownMessageSender;

    @Mock
    private CreateAttestationSubKeyVerifier createSubKeyVerifier;

    @Mock
    private S10AttestationRevocationService s10AttestationRevocationService;

    @Mock
    private S10CacheEntityService s10CacheEntityService;

    @Mock
    private SigmaM2DeviceIdVerifier deviceIdVerifier;

    @InjectMocks
    private CreateDeviceAttestationSubKeyComponent sut;

    private CreateAttestationSubKeyResponseBuilder createSubKeyResponseBuilder =
        new CreateAttestationSubKeyResponseBuilder();

    @Test
    void perform_Success() {
        // given
        mockAppContext();
        mockDatabaseConnection();

        createSubKeyResponseBuilder.setSdmSessionId(SDM_SESSION_ID);
        doReturn(createSubKeyResponseBuilder)
            .when(createSubKeyMessageSender)
            .send(eq(transportLayer), eq(commandLayer), eq(CONTEXT), anyInt(),
                eq(PUF_TYPE), any(EcdhKeyPair.class));

        when(s10AttestationRevocationService.checkAndRetrieve(DEVICE_ID,
            PufType.getPufTypeHex(PufType.EFUSE))).thenReturn(pufPubKey);

        // when
        VerifierExchangeResponse result = sut.perform(appContext, CONTEXT, PUF_TYPE, DEVICE_ID);

        // then
        Assertions.assertEquals(VerifierExchangeResponse.OK, result);
        verify(createSubKeyVerifier).verify(any(), any(), eq(pufPubKey));
        verify(teardownMessageSender).send(transportLayer, commandLayer, SDM_SESSION_ID);
        verify(deviceIdVerifier).verify(eq(DEVICE_ID), any());
    }

    private void mockAppContext() {
        when(appContext.getTransportLayer()).thenReturn(transportLayer);
        when(appContext.getCommandLayer()).thenReturn(commandLayer);
    }

    private void mockDatabaseConnection() {
        when(appContext.getSqLiteHelper()).thenReturn(sqLiteHelper);
        when(sqLiteHelper.getS10CacheEntityService()).thenReturn(s10CacheEntityService);
        when(s10CacheEntityService.store(any())).thenReturn(s10CacheEntityService);
    }
}
