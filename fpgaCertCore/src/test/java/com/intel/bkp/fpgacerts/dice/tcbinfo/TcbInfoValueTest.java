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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import com.intel.bkp.fpgacerts.dice.tcbinfo.vendorinfo.MaskedVendorInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

@ExtendWith(MockitoExtension.class)
class TcbInfoValueTest {

    private static final FwIdField FWIDS = new FwIdField("HASH_ALG", "DIGEST");
    private static final MaskedVendorInfo VENDOR_INFO = new MaskedVendorInfo("VENDOR_INFO");

    private static TcbInfo TCB_INFO;

    @BeforeAll
    static void init() {
        final var map = Map.of(
            TcbInfoField.FWIDS, FWIDS,
            TcbInfoField.VENDOR_INFO, VENDOR_INFO
        );
        TCB_INFO = new TcbInfo(map);
    }

    @Test
    void from_Empty() {
        // when
        final TcbInfoValue result = TcbInfoValue.from(new TcbInfo());

        // then
        Assertions.assertNull(result.getFwid());
        Assertions.assertNull(result.getMaskedVendorInfo());
    }

    @Test
    void from_AllSet() {
        // when
        final TcbInfoValue result = TcbInfoValue.from(TCB_INFO);

        // then
        Assertions.assertEquals(FWIDS, result.getFwid());
        Assertions.assertEquals(VENDOR_INFO, result.getMaskedVendorInfo());
    }

    @Test
    void toString_Empty() {
        // given
        final String expected = "TcbInfoValue( )";

        // when
        final String result = TcbInfoValue.from(new TcbInfo()).toString();

        // then
        Assertions.assertEquals(expected, result);
    }

    @Test
    void toString_AllSet() {
        // given
        final String expected = "TcbInfoValue( fwid=FwIdField( hashAlg=HASH_ALG digest=DIGEST ) "
                + "maskedVendorInfo=MaskedVendorInfo( vendorInfo=VENDOR_INFO ) )";

        // when
        final String result = TcbInfoValue.from(TCB_INFO).toString();

        // then
        Assertions.assertEquals(expected, result);
    }
}
