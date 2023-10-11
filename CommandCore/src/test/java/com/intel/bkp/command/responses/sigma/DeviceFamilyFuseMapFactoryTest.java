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

package com.intel.bkp.command.responses.sigma;

import org.junit.jupiter.api.Test;

import static com.intel.bkp.command.responses.sigma.DeviceFamilyFuseMap.FM568;
import static com.intel.bkp.command.responses.sigma.DeviceFamilyFuseMap.S10;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class DeviceFamilyFuseMapFactoryTest {

    @Test
    public void get_WithS10_Success() {
        // given
        final DeviceFamilyFuseMapFactory sut = new DeviceFamilyFuseMapFactory(S10.getByteFromOrdinal());

        // when
        final byte[] result = sut.get();

        // then
        assertEquals(S10.getEfuseValuesFieldLen(), result.length);
    }

    @Test
    public void get_WithFM568_Success() {
        // given
        final DeviceFamilyFuseMapFactory sut = new DeviceFamilyFuseMapFactory(FM568.getByteFromOrdinal());

        // when
        final byte[] result = sut.get();

        // then
        assertEquals(FM568.getEfuseValuesFieldLen(), result.length);
    }

}
