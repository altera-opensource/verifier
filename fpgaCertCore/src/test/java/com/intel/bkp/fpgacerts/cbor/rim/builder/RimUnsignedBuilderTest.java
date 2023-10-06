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

import com.intel.bkp.fpgacerts.cbor.LocatorItem;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.rim.parser.RimCoMIDParser;
import com.intel.bkp.test.FileUtils;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static com.intel.bkp.test.FileUtils.TEST_FOLDER;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RimUnsignedBuilderTest {

    private static final RimCoMIDParser RIM_CO_MID_CONVERTER = RimCoMIDParser.instance();

    private static final String MANIFEST_ID = "51AC25B8DC58405CB4C94772120BA68A";
    private static final String COM_ID = "A301A100504714D26D0E044CD8BEE14EB53541B8830281A200714669726D77617265206D616E"
        + "696665737402810004A2008282A100A40169696E74656C2E636F6D02664167696C65780300040081A101A201D902280002818207583"
        + "0302E69BA6E3FAC340A57561234E88BFEB2FE373BCE4D4A28C244809CB467C31CA39874CD0D3F346FCA2A9AE874A1D66B82A100A401"
        + "69696E74656C2E636F6D02664167696C65780301040081A101A201D902280002818207583032883E2526F54EA21FBF99642A8F56E78"
        + "7A0319D1D0E2AF84C36352E9A760EE80EA6C427098D17D26F65723C0C1C66EA018182A100A300D86F4C6086480186F84D010F048148"
        + "0169696E74656C2E636F6D030181A101A100A2007372656C656173652D323032332E32382E312E310103";

    private static final String DESIGN_COM_ID = "A301A100507154E6756A064C95A2E5AD61CBF7B0C00281A2006D44657369676E20417"
        + "574686F7202810004A2008582A100A300D86F4B6086480186F84D010F04010169696E74656C2E636F6D030281A101A204D902304800"
        + "000000030000000548FFFFFFFF000000FF82A100A300D86F4B6086480186F84D010F04020169696E74656C2E636F6D030281A101A10"
        + "28182075830AB822974FAD8A6E3AD95916AF199AC189015CAD15613CD161EC33090E9D13EBD9C21B952CAC8F856411F42238FFAA8C4"
        + "82A100A300D86F4B6086480186F84D010F04030169696E74656C2E636F6D030281A101A1028182075830C0AA77F5D2214BA0A8AE297"
        + "6418A1ECC4424C996AB5EEA8FE9B75E0B9D167EF8ADDA90D97DE60C241F70D4AE8E52FF1F82A100A300D86F4B6086480186F84D010F"
        + "04050169696E74656C2E636F6D030281A101A1028182075830B581557A36836ABA4BA69D9B2C4252CF29281A996C92202DDA2E9112F"
        + "A458CBB1522367EE54E82B026E61C0B62DADF7682A100A300D86F4C6086480186F84D010F0481480169696E74656C2E636F6D030181"
        + "A101A100A2007272656C656173652D323032312E332E342E320103018182A100A200D86F4C6086480186F84D010F0481490169696E7"
        + "4656C2E636F6D81A101A100A10060";

    private static final String LINK_CER =
        "https://tsci.intel.com/content/IPCS/certs/RIM_Signing_agilex_5WL28Ty-Nta3Si1dR3ralQ7jFHw.cer";
    private static final String LINK_XRIM =
        "https://tsci.intel.com/content/IPCS/crls/RIM_Signing_agilex_5WL28Ty-Nta3Si1dR3ralQ7jFHw.xrim";
    private static final String LINK_RIM =
        "https://tsci.intel.com/content/IPCS/rims/agilex_L1_c3jAnhF5MTYncnRlDh_Ggr-T7lvK.rim";
    private static final String PROFILE = "6086480186F84D010F06";

    private final RimUnsignedBuilder sut = RimUnsignedBuilder.instance().standalone();

    @Test
    void build_WithFwCoRim_Success() throws Exception {
        // given
        final byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "fw_rim_unsigned.rim");
        final String cborDataHex = toHex(cborData);
        final List<LocatorItem> locators = new ArrayList<>();
        locators.add(new LocatorItem(LocatorType.CER, LINK_CER));
        locators.add(new LocatorItem(LocatorType.XCORIM, LINK_XRIM));

        final var entity = RimUnsigned.builder()
            .manifestId(MANIFEST_ID)
            .comIds(List.of(RIM_CO_MID_CONVERTER.parse(fromHex(COM_ID))))
            .locators(locators)
            .profile(List.of(PROFILE))
            .build();

        // when
        final byte[] actual = sut.designRim(false).build(entity);

        // then
        assertEquals(cborDataHex, toHex(actual));
    }

    @Test
    void build_WithDesignCoRim_Success() throws Exception {
        // given
        final byte[] cborData = FileUtils.readFromResources(TEST_FOLDER, "design_rim_unsigned.rim");
        final String cborDataHex = toHex(cborData);
        final List<LocatorItem> locators = List.of(new LocatorItem(LocatorType.CORIM, LINK_RIM));

        final var entity = RimUnsigned.builder()
            .manifestId("73A635A8F5614D8CB8BAC8B5B8B42472")
            .comIds(List.of(RIM_CO_MID_CONVERTER.parse(fromHex(DESIGN_COM_ID))))
            .locators(locators)
            .profile(List.of(PROFILE))
            .build();

        // when
        final byte[] actual = sut.designRim(true).build(entity);

        // then
        assertEquals(cborDataHex, toHex(actual));
    }
}
