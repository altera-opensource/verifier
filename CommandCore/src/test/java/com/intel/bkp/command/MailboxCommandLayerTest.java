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

package com.intel.bkp.command;

import com.intel.bkp.command.exception.JtagResponseException;
import com.intel.bkp.command.messages.common.GetCertificateMessageBuilder;
import com.intel.bkp.command.messages.common.GetChipIdMessage;
import com.intel.bkp.command.model.CommandIdentifier;
import com.intel.bkp.command.model.Message;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.command.model.CertificateRequestType.FIRMWARE;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MailboxCommandLayerTest {

    private MailboxCommandLayer sut = new MailboxCommandLayer();

    @Test
    void create_commandWithoutData_Success() {
        // given
        final Message message = new GetChipIdMessage();
        final CommandIdentifier command = CommandIdentifier.GET_CHIPID;
        final byte[] expected = fromHex("12000010");

        // when
        final byte[] result = sut.create(message, command);

        // then
        assertArrayEquals(expected, result);
    }

    @Test
    void create_commandWithData_Success() {
        // given
        final Message message = new GetCertificateMessageBuilder().withType(FIRMWARE).build();
        final CommandIdentifier command = CommandIdentifier.GET_ATTESTATION_CERTIFICATE;
        final byte[] expected = fromHex("8111001001000000");

        // when
        final byte[] result = sut.create(message, command);

        // then
        assertArrayEquals(expected, result);
    }

    @Test
    void retrieve_Success() {
        // given
        final CommandIdentifier command = CommandIdentifier.GET_CHIPID;
        final byte[] responseDataWithHeader = fromHex("00200010695D48644C08D307");
        final byte[] expected = fromHex("695D48644C08D307");

        // when
        final byte[] result = sut.retrieve(responseDataWithHeader, command);

        // then
        assertArrayEquals(expected, result);
    }

    @Test
    void retrieve_HeaderValidationFails_Throws() {
        // given
        final CommandIdentifier command = CommandIdentifier.GET_CHIPID;
        final byte[] tooShortResponse = fromHex("002000");

        // when
        assertThrows(JtagResponseException.class, () -> sut.retrieve(tooShortResponse, command));
    }
}
