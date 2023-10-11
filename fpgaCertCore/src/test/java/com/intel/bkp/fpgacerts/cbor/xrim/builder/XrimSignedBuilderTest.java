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

package com.intel.bkp.fpgacerts.cbor.xrim.builder;

import com.intel.bkp.fpgacerts.cbor.xrim.XrimSigned;
import com.intel.bkp.fpgacerts.cbor.xrim.parser.XrimProtectedParser;
import com.intel.bkp.fpgacerts.cbor.xrim.parser.XrimUnsignedParser;
import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class XrimSignedBuilderTest {

    private final XrimSignedBuilder sut = XrimSignedBuilder.instance();

    @Test
    void build_WithXCoRim_Success() throws Exception {
        // given
        byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "fw_xrim_signed.xrim");
        final XrimSigned entity = prepareXCoRimEntity();

        // when
        final byte[] bytes = sut.build(entity);

        // then
        assertEquals(toHex(cborData), toHex(bytes));
    }

    @Test
    void build_WithDesignXCoRim_Success() throws Exception {
        // given
        byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "design_xrim_signed.xrim");
        final XrimSigned entity = prepareDesignXCoRimEntity();

        // when
        final byte[] bytes = sut.build(entity);

        // then
        assertEquals(toHex(cborData), toHex(bytes));
    }

    private XrimSigned prepareXCoRimEntity() {
        final String signature = "79C585DC624605C3AC84B4936DF7E7737117433DD57144F064478FD592A5D9D5B4188303041AAEFFF783"
            + "E4E5C8C2064DF41F29C8C49B071D47E1A1480BE0C04461151DB591CD9CF72212C5C742AEC170FE6982721332F4656D60B10657F"
            + "0F187";

        final String protectedRim = "A401382203756170706C69636174696F6E2F7872696D2B63626F72045400000000000000000000000"
            + "0000000000000000009582BA200A1006F4669726D7761726520417574686F7201C074393939392D31322D33315432333A35393A"
            + "35395A";

        final String unsignedData = "D9020EA20081A3006F4669726D7761726520417574686F7201D820600281010181782035316163323"
            + "56238646335383430356362346339343737323132306261363861";

        return XrimSigned.builder()
            .protectedData(XrimProtectedParser.instance().parse(fromHex(protectedRim)))
            .payload(XrimUnsignedParser.instance().parse(fromHex(unsignedData)))
            .signature(signature)
            .build();
    }

    private XrimSigned prepareDesignXCoRimEntity() {
        final String protectedRim = "A401382203756170706C69636174696F6E2F7872696D2B63626F7204543D713C32AC3740FD37C7E65"
            + "DAE8227D4C2021584095828A200A1006C58436F72696D204F776E657201C074323032332D30382D31385430393A30393A33345A";

        final String unsignedData = "D9020EA20081A3006E64657369676E20617574686F723101D82063616263028101018261316133";

        final String signature = "305D87DE6A99E6C5AF917E226A1302F310FFC8C357565316DE43C90E0948F8979414941A65F1F1DC31EC"
            + "0381C4E5D0A17FDBCEDE8C8280C2BB37BACEC4C63553E140914F5345BB16D410A46CD506CBE3A694D75E0BCB16FD331532611A2"
            + "ABF0D";

        return XrimSigned.builder()
            .protectedData(XrimProtectedParser.instance().parse(fromHex(protectedRim)))
            .payload(XrimUnsignedParser.instance().parse(fromHex(unsignedData)))
            .signature(signature)
            .build();
    }
}
