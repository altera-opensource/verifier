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

package com.intel.bkp.fpgacerts.cbor.rim.builder;

import com.intel.bkp.fpgacerts.cbor.rim.RimSigned;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimProtectedHeaderParser;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimSignedParser;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimUnsignedParser;
import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RimSignedBuilderTest {

    private final RimSignedBuilder sut = RimSignedBuilder.instance();

    @Test
    void build_Success() throws Exception {
        // given
        byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "fw_rim_signed.rim");
        final RimSigned entity = prepareEntity();

        // when
        final byte[] bytes = sut.build(entity);

        // then
        assertEquals(toHex(cborData), toHex(bytes));
    }

    @Test
    void build_WithDesignRim_Success() throws Exception {
        // given
        final byte[] rawSignedData = FileUtils.readFromResources(TEST_FOLDER, "design_rim_signed.rim");
        final RimSigned signed = RimSignedParser.instance().parse(rawSignedData);

        // when
        final byte[] actual = sut.designRim().build(signed);

        // then
        assertEquals(toHex(rawSignedData), toHex(actual));
    }

    private static RimSigned prepareEntity() {
        final String signature = "804440C3ADD300F0CD9635BCD82A4D253A6DD119AB620589196DF799E6B63591DA96D6D6CA21D2032EF5"
            + "7220F56A3E047AFED8D68E04BFB9EA69A91155B974C2D3644DDFEB184D939FF2B827ABD1F0E69EE765558CDDCBB0DEC82979B11"
            + "A56C3";

        final String unsignedData =
            "D901F5A4005051AC25B8DC58405CB4C94772120BA68A0181D901FA590126A301A100504714D26D0E044CD8BEE14EB53541B883028"
                + "1A200714669726D77617265206D616E696665737402810004A2008282A100A40169696E74656C2E636F6D02664167696C65"
                + "780300040081A101A201D9022800028182075830302E69BA6E3FAC340A57561234E88BFEB2FE373BCE4D4A28C244809CB46"
                + "7C31CA39874CD0D3F346FCA2A9AE874A1D66B82A100A40169696E74656C2E636F6D02664167696C65780301040081A101A2"
                + "01D902280002818207583032883E2526F54EA21FBF99642A8F56E787A0319D1D0E2AF84C36352E9A760EE80EA6C427098D1"
                + "7D26F65723C0C1C66EA018182A100A300D86F4C6086480186F84D010F0481480169696E74656C2E636F6D030181A101A100"
                + "A2007372656C656173652D323032332E32382E312E3101030282A100D820785C68747470733A2F2F747363692E696E74656"
                + "C2E636F6D2F636F6E74656E742F495043532F63657274732F52494D5F5369676E696E675F6167696C65785F35574C323854"
                + "792D4E74613353693164523372616C51376A4648772E636572A100D820785C68747470733A2F2F747363692E696E74656C2"
                + "E636F6D2F636F6E74656E742F495043532F63726C732F52494D5F5369676E696E675F6167696C65785F35574C323854792D"
                + "4E74613353693164523372616C51376A4648772E7872696D0381D86F4A6086480186F84D010F06";

        final String protectedRim = "A401382203746170706C69636174696F6E2F72696D2B63626F7204540000000000000000000000000"
            + "000000000000000085848A20082A1006F4669726D7761726520417574686F72A10077434E3D496E74656C3A4167696C65783A4D"
            + "616E5369676E01A101C074393939392D31322D33315432333A35393A35395A";

        return RimSigned.builder()
            .protectedData(RimProtectedHeaderParser.instance().parse(fromHex(protectedRim)))
            .payload(RimUnsignedParser.instance().parse(fromHex(unsignedData)))
            .signature(signature)
            .build();
    }
}
