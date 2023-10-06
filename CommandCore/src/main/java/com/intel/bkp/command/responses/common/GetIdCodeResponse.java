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

package com.intel.bkp.command.responses.common;

import com.intel.bkp.command.logger.ILogger;
import com.intel.bkp.command.model.Response;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import lombok.Getter;
import lombok.Setter;

import java.util.Locale;

import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toFormattedHex;
import static com.intel.bkp.utils.HexConverter.toHex;

/**
 * Example JTAG IDCODE response: 6341D0DD.
 * <p> 6: This is the first part of the IDCODE. It often represents the manufacturer's ID or code, indicating the FPGA
 * manufacturer.</p>
 * <p> 34: The second part of the IDCODE, "34," represents the device family and series. This code indicates the
 * specific
 * type or series of FPGA within the manufacturer's product lineup.</p>
 * <p> 1D0DD: The last part of the IDCODE, "1D0DD," typically signifies the device-specific part number or variant.
 * This segment uniquely identifies the particular FPGA model and its features.</p>
 */
@Getter
@Setter
public class GetIdCodeResponse implements Response, ILogger {

    private byte manufacturer;
    private byte familyId;
    private String deviceSpecificNumber;

    @Override
    public byte[] array() {
        final String idCode = toHex(manufacturer).substring(1, 2) + toHex(familyId) + deviceSpecificNumber;
        return ByteSwap.getSwappedArrayByInt(fromHex(idCode), ByteSwapOrder.B2L);
    }

    @Override
    public String toString() {
        return "GetIdCodeResponse { "
            + "idCode = " + toFormattedHex(array())
            + ", manufacturer = " + toFormattedHex(manufacturer)
            + ", familyId = " + toFormattedHex(familyId) + " (" + familyId + ")"
            + ", deviceSpecificNumber = 0x" + deviceSpecificNumber.toLowerCase(Locale.ROOT)
            + " }";
    }
}
