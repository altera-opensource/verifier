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

package com.intel.bkp.protocol.spdm.service;

import com.intel.bkp.protocol.spdm.exceptions.UnsupportedSpdmVersionException;
import com.intel.bkp.protocol.spdm.jna.model.SpdmProtocol;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.intel.bkp.protocol.spdm.service.SpdmGetVersionMessageSender.SPDM_SUPPORTED_VERSION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
class SpdmGetVersionMessageSenderTest {

    @Mock
    private SpdmProtocol spdmProtocol;

    @InjectMocks
    private SpdmGetVersionMessageSender sut;

    @Test
    void send_returnsSupportedVersion_Success() throws Exception {
        // given
        doReturn(SPDM_SUPPORTED_VERSION).when(spdmProtocol).getVersion();

        // when
        final String result = sut.send();

        // then
        assertEquals(SPDM_SUPPORTED_VERSION, result);
    }

    @Test
    void send_returnsLowerVersion_Throws() throws Exception {
        // given
        doReturn("01").when(spdmProtocol).getVersion();

        // when-then
        assertThrows(UnsupportedSpdmVersionException.class, () -> sut.send());
    }

    @Test
    void send_returnsHigherVersion_Throws() throws Exception {
        // given
        doReturn("FF").when(spdmProtocol).getVersion();

        // when-then
        assertThrows(UnsupportedSpdmVersionException.class, () -> sut.send());
    }
}
