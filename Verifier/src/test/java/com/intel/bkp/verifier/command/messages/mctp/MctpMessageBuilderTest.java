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

package com.intel.bkp.verifier.command.messages.mctp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class MctpMessageBuilderTest {

    private static final byte[] PAYLOAD_NO_PADDING = {1, 2, 3, 4};
    private static final byte[] PAYLOAD_PADDING_1 = {1};
    private static final byte[] PAYLOAD_PADDING_1_EXPECTED = {1, 0, 0, 0};
    private static final byte[] PAYLOAD_PADDING_2 = {1, 2, 3, 4, 5, 6};
    private static final byte[] PAYLOAD_PADDING_2_EXPECTED = {1, 2, 3, 4, 5, 6, 0, 0};

    private MctpMessageBuilder sut;

    @BeforeEach
    void setUp() {
        sut = new MctpMessageBuilder();
    }

    @Test
    void build_WithPayloadNoPadding_Success() {
        // given
        final MctpMessage result = prepareMctpMessageWithPayload(PAYLOAD_NO_PADDING);

        // then
        assertArrayEquals(sut.getHeader(), result.getHeader());
        assertArrayEquals(PAYLOAD_NO_PADDING, result.getPayload());
    }

    @Test
    void parse_WithPayloadNoPadding_Success() {
        // given
        final MctpMessage message = prepareMctpMessageWithPayload(PAYLOAD_NO_PADDING);

        // when
        final MctpMessageBuilder result = sut.parse(message.array());

        // then
        assertArrayEquals(sut.getHeader(), result.getHeader());
        assertArrayEquals(PAYLOAD_NO_PADDING, result.getPayload());
    }

    @Test
    void parse_WithPayloadWithPadding_AddsProperPadding() {
        // given
        final MctpMessage message = prepareMctpMessageWithPayload(PAYLOAD_PADDING_1);

        // when
        final MctpMessageBuilder result = sut.parse(message.array());

        // then
        assertArrayEquals(sut.getHeader(), result.getHeader());
        assertArrayEquals(PAYLOAD_PADDING_1_EXPECTED, result.getPayload());
    }

    @Test
    void parse_WithPayloadWithPadding2_AddsProperPadding() {
        // given
        final MctpMessage message = prepareMctpMessageWithPayload(PAYLOAD_PADDING_2);

        // when
        final MctpMessageBuilder result = sut.parse(message.array());

        // then
        assertArrayEquals(sut.getHeader(), result.getHeader());
        assertArrayEquals(PAYLOAD_PADDING_2_EXPECTED, result.getPayload());
    }

    private MctpMessage prepareMctpMessageWithPayload(byte[] payloadPadding2) {
        sut.withPayload(ByteBuffer.wrap(payloadPadding2));
        return sut.build();
    }
}
