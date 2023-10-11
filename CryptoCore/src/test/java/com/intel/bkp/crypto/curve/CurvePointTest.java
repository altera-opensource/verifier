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

package com.intel.bkp.crypto.curve;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.impl.EcUtils;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;

import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_384;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_KEY;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CurvePointTest {

    @AllArgsConstructor
    private enum TestPublicKey {
        PUB_48X49Y(
            "52A3BF8C3082712E005DDAD688829437AE283F78B42D8DF24157332BDC00D188613A4072E6A49FEADCA4C2B2FD2A8843",
            "00A4A46CEAA31D2CC6F918C9DBFC0CA70EF7AE3BC458DB458D3DB0223714FD0C6AC7FC54A418187E64F03AAFAC72315042",
            "af12b1943a0ae07eab30ab81fcf11a979181a137391c13971a7bd4236c8d04d524d6dfd1ce2b30c4b20bd25d8e4361f2"
        ),
        PUB_48XY(
            "0CE647F8DBB870A11437FE2780CF8AC8E5E4A21D08970679268CDE7892F06120E321EC2584E04985AE0E7FDCC2C71A32",
            "7F14B32A7E576F90F46A8BC8601695679E73C7FBE38A735FCAD507B9873C78E9C8CEB025BB15243DCE1D79E369D6DE7A",
            "c1dd9ee0f26bb5f4c6bbc9ff69339a586fe3c65c64bacbdfd71b3b0f7c0993543f0b2935d13ddf868ad4e0fe9f241248"
        ),
        PUB_49X47Y(
            "00BB828B172E29E2EA2A735D8A7FFF3BF0ECD7AA0D5F08D5A0DA945C4847CD8F8DDAAFD9C3BFC46408F724B8DBA14FA900",
            "1B99EBA17FD014C98CAA7B99A2685E6439D6D7DF7EF94C27BCFC91759C05334D2338F39D8A6F7B74A145A43B323896",
            "b7165c7217d4b65fbc2f4dfb7012174a7cf47cc4191738d1435835972cca69671fa4256b6b995603cb6712193a0b0638"
        );
        private final String pointX;
        private final String pointY;
        private final String expectedFingerprint;

        @SneakyThrows
        public PublicKey getKey() {
            return CryptoUtils.toEcPublicBC(
                fromHex("%s%s".formatted(preparePoint(pointX), preparePoint(pointY))), EC_KEY, EC_CURVE_SPEC_384
            );
        }
    }

    private static final String EC_PUB_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n" +
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEcD0WjXYNbYtg2xyk8IoNApOXyBH59DrU\n" +
        "B/nMhKd5EAaLYpp+luEB4O3sVB2goO7fFWuEA5UBDXoG//N67lsibE7FHkE+VLpx\n" +
        "m7AwihLUoYhf7mC+GtXCbQQX5w1W8lu0\n" +
        "-----END PUBLIC KEY-----";

    private static final String EC_PUB_KEY_ENCODED =
        "3076301006072A8648CE3D020106052B8104002203620004703D168D760D6D8B60DB1CA4F08A0D0"
            + "29397C811F9F43AD407F9CC84A77910068B629A7E96E101E0EDEC541DA0A0EEDF156B840395010D7A06FFF37AEE5B226C4EC51E4"
            + "13E54BA719BB0308A12D4A1885FEE60BE1AD5C26D0417E70D56F25BB4";
    private static final String EXPECTED_A =
        "703D168D760D6D8B60DB1CA4F08A0D029397C811F9F43AD407F9CC84A77910068B629A7E96E101E0EDEC541DA0A0EEDF";
    private static final String EXPECTED_B =
        "156B840395010D7A06FFF37AEE5B226C4EC51E413E54BA719BB0308A12D4A1885FEE60BE1AD5C26D0417E70D56F25BB4";

    @Test
    void from_WithNotEcPubKey_ThrowsException() {
        // given
        final PublicKey rsaPubKey = KeyGenUtils.genRsa3072().getPublic();

        // when-then
        assertThrows(IllegalArgumentException.class, () -> CurvePoint.from(rsaPubKey, CurveSpec.C384));
    }

    @Test
    void from_WithPubKeyOnly_WithEcKey384_Success() {
        // given
        final PublicKey ecPubKey = KeyGenUtils.genEc384().getPublic();

        // when
        final CurvePoint curvePoint = CurvePoint.from(ecPubKey);

        // then
        assertEquals(CurveSpec.C384, curvePoint.getCurveSpec());
    }

    @Test
    void from_WithPubKeyOnly_WithRsa_ThrowsException() {
        // given
        final PublicKey rsaPubKey = KeyGenUtils.genRsa3072().getPublic();

        // when-then
        assertThrows(IllegalArgumentException.class, () -> CurvePoint.from(rsaPubKey));
    }

    @ParameterizedTest
    @EnumSource(TestPublicKey.class)
    void from_WithPubKeyAndSpec_Success(TestPublicKey testPublicKey) {
        // given
        final PublicKey publicKey = testPublicKey.getKey();

        // when
        final CurvePoint point = CurvePoint.from(publicKey, CurveSpec.C384);

        // then
        assertEquals(preparePoint(testPublicKey.pointX), toHex(point.getPointA()));
        assertEquals(preparePoint(testPublicKey.pointY), toHex(point.getPointB()));
    }

    @ParameterizedTest
    @EnumSource(TestPublicKey.class)
    void from_WithStringPointXAndY_Success(TestPublicKey testPublicKey) {
        // when
        final CurvePoint point = CurvePoint.from(testPublicKey.pointX, testPublicKey.pointY, CurveSpec.C384);

        // then
        assertEquals(preparePoint(testPublicKey.pointX), toHex(point.getPointA()));
        assertEquals(preparePoint(testPublicKey.pointY), toHex(point.getPointB()));
    }

    @ParameterizedTest
    @EnumSource(TestPublicKey.class)
    void from_WithBytePointXY_ResultsWithSameXY(TestPublicKey testPublicKey) {
        // given
        byte[] pointX = fromHex(testPublicKey.pointX);
        byte[] pointY = fromHex(testPublicKey.pointY);

        // when
        final CurvePoint point = CurvePoint.from(pointX, pointY, CurveSpec.C384);

        // then
        assertEquals(preparePoint(testPublicKey.pointX), point.getHexPointA());
        assertEquals(preparePoint(testPublicKey.pointY), point.getHexPointB());
    }

    @ParameterizedTest
    @EnumSource(TestPublicKey.class)
    void from_ByteBuffer_Success(TestPublicKey testPublicKey) {
        // given
        final String expected = prepareConcatenatedXY(testPublicKey);

        // when
        final CurvePoint point = CurvePoint.from(ByteBufferSafe.wrap(fromHex(expected)), CurveSpec.C384);

        // then
        assertEquals(expected, toHex(point.getAlignedDataToSize()));
    }

    @ParameterizedTest
    @EnumSource(TestPublicKey.class)
    void fromPubKey_PlainXY_Success(TestPublicKey testPublicKey) {
        // given
        final String expected = prepareConcatenatedXY(testPublicKey);

        // when
        final CurvePoint point = CurvePoint.fromPubKey(fromHex(expected), CurveSpec.C384);

        // then
        assertEquals(expected, toHex(point.getAlignedDataToSize()));
    }

    @Test
    void fromPubKey_EncodedPubKeyWithSpec_Success() throws Exception {
        // when
        final CurvePoint point = CurvePoint.fromPubKeyEncoded(fromHex(EC_PUB_KEY_ENCODED), CurveSpec.C384);

        // then
        assertEquals(EXPECTED_A, point.getHexPointA());
        assertEquals(EXPECTED_B, point.getHexPointB());
    }

    @Test
    void fromPubKey_EncodedPubKey_Success() throws Exception {
        // when
        final CurvePoint point = CurvePoint.fromPubKeyEncoded(fromHex(EC_PUB_KEY_ENCODED));

        // then
        assertEquals(EXPECTED_A, point.getHexPointA());
        assertEquals(EXPECTED_B, point.getHexPointB());
    }
    @Test
    void fromPubKeyPem_EncodedPubKey_Success() throws Exception {
        // when
        final CurvePoint point = CurvePoint.fromPubKeyPem(EC_PUB_KEY_PEM.getBytes());

        // then
        assertEquals(EXPECTED_A, point.getHexPointA());
        assertEquals(EXPECTED_B, point.getHexPointB());
    }

    @ParameterizedTest
    @EnumSource(TestPublicKey.class)
    void generateFingerprint_Success(TestPublicKey testPublicKey) {
        // given
        final String expected = prepareConcatenatedXY(testPublicKey);
        final CurvePoint sut = CurvePoint.fromPubKey(fromHex(expected), CurveSpec.C384);

        // when
        final String fingerprint = sut.generateFingerprint();

        // then
        assertEquals(testPublicKey.expectedFingerprint, fingerprint);
    }

    @ParameterizedTest
    @EnumSource(TestPublicKey.class)
    void getAlignedDataToSize_WithBytePointXY_ResultsWithAlignedToCurveSizeXY(TestPublicKey testPublicKey) {
        // given
        final PublicKey publicKey = testPublicKey.getKey();
        final String expected = prepareConcatenatedXY(testPublicKey);

        // when
        final byte[] data = CurvePoint.from(publicKey, CurveSpec.C384).getAlignedDataToSize();

        // then
        assertEquals(expected, toHex(data));
        assertEquals(CurveSpec.C384.getSize() * 2, data.length);
    }

    @Test
    void fromSignature_Success() throws Exception {
        // given
        final KeyPair ec384Keys = KeyGenUtils.genEc384();
        final byte[] signature = EcUtils.signEcData(ec384Keys.getPrivate(), "test".getBytes(StandardCharsets.UTF_8),
            CryptoConstants.SHA384_WITH_ECDSA, CryptoUtils.getBouncyCastleProvider()
        );

        // then
        final CurvePoint curvePoint = CurvePoint.fromSignature(signature, () -> CurveSpec.C384);

        // Then
        assertEquals(CurveSpec.C384, curvePoint.getCurveSpec());
    }

    private static String preparePoint(String point) {
        final int expectedSize = CurveSpec.C384.getSize() * 2;
        final int actualSize = point.length();
        if (expectedSize == actualSize) {
            return point;
        } else if (expectedSize < actualSize) {
            return point.substring(2);
        } else {
            return "00" + point;
        }
    }

    private static String prepareConcatenatedXY(TestPublicKey testData) {
        final String pointXExp = preparePoint(testData.pointX);
        final String pointYExp = preparePoint(testData.pointY);
        return "%s%s".formatted(pointXExp, pointYExp);
    }
}
