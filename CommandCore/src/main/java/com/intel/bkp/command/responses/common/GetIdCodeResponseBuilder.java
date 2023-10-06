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

import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.ByteSwap;
import com.intel.bkp.utils.ByteSwapOrder;
import lombok.Setter;

import static com.intel.bkp.utils.HexConverter.toHex;

@Setter
public class GetIdCodeResponseBuilder {

    private static final int ID_CODE_RESPONSE_REQUIRED_LEN = 4;
    private static final int DEVICE_SPECIFIC_NUMBER_REQUIRED_LEN = 5;

    private byte manufacturer;
    private byte familyId;
    private String deviceSpecificNumber;

    public void setDeviceSpecificNumber(String deviceSpecificNumber) {
        if (deviceSpecificNumber.length() != DEVICE_SPECIFIC_NUMBER_REQUIRED_LEN) {
            throw new IllegalArgumentException("Device specific number length must be equal to %d bytes."
                .formatted(DEVICE_SPECIFIC_NUMBER_REQUIRED_LEN));
        }

        this.deviceSpecificNumber = deviceSpecificNumber;
    }

    public GetIdCodeResponse build() {
        final var getIdCodeResponse = new GetIdCodeResponse();
        getIdCodeResponse.setManufacturer(manufacturer);
        getIdCodeResponse.setFamilyId(familyId);
        getIdCodeResponse.setDeviceSpecificNumber(deviceSpecificNumber);
        return getIdCodeResponse;
    }

    public GetIdCodeResponseBuilder parse(byte[] message) {
        byte[] idCode = new byte[ID_CODE_RESPONSE_REQUIRED_LEN];

        ByteBufferSafe.wrap(message).getAll(idCode);
        idCode = ByteSwap.getSwappedArrayByInt(idCode, ByteSwapOrder.L2B);

        final String idCodeHex = toHex(idCode);

        try {
            final String manufacturerHex = idCodeHex.substring(0, 1);
            final String familyIdHex = idCodeHex.substring(1, 3);
            final String deviceSpecificNumberHex = idCodeHex.substring(3, 8);

            manufacturer = Byte.parseByte(manufacturerHex, 16);
            familyId = Byte.parseByte(familyIdHex, 16);
            deviceSpecificNumber = deviceSpecificNumberHex;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse IDCODE response.", e);
        }

        return this;
    }
}
