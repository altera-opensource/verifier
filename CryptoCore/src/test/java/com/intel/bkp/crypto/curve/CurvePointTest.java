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

package com.intel.bkp.crypto.curve;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.TestUtil;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import com.intel.bkp.crypto.impl.EcUtils;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;

import static com.intel.bkp.crypto.constants.CryptoConstants.EC_CURVE_SPEC_384;
import static com.intel.bkp.crypto.constants.CryptoConstants.EC_KEY;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;

class CurvePointTest {

    @AllArgsConstructor
    private enum TestPublicKey {
        PUB_48X49Y(
            "52A3BF8C3082712E005DDAD688829437AE283F78B42D8DF24157332BDC00D188613A4072E6A49FEADCA4C2B2FD2A8843",
            "00A4A46CEAA31D2CC6F918C9DBFC0CA70EF7AE3BC458DB458D3DB0223714FD0C6AC7FC54A418187E64F03AAFAC72315042"
        ),
        PUB_48XY(
            "0CE647F8DBB870A11437FE2780CF8AC8E5E4A21D08970679268CDE7892F06120E321EC2584E04985AE0E7FDCC2C71A32",
            "7F14B32A7E576F90F46A8BC8601695679E73C7FBE38A735FCAD507B9873C78E9C8CEB025BB15243DCE1D79E369D6DE7A"
        ),
        PUB_49X47Y(
            "00BB828B172E29E2EA2A735D8A7FFF3BF0ECD7AA0D5F08D5A0DA945C4847CD8F8DDAAFD9C3BFC46408F724B8DBA14FA900",
            "1B99EBA17FD014C98CAA7B99A2685E6439D6D7DF7EF94C27BCFC91759C05334D2338F39D8A6F7B74A145A43B323896"
        );
        private final String pointX;
        private final String pointY;

        @SneakyThrows
        public PublicKey getKey() {
            return CryptoUtils.toEcPublicBC(
                fromHex("%s%s".formatted(preparePoint(pointX), preparePoint(pointY))), EC_KEY, EC_CURVE_SPEC_384
            );
        }
    }

    @Test
    void from_WithNotEcPubKey_ThrowsException() throws KeystoreGenericException {
        // given
        final PublicKey rsaPubKey = TestUtil.genRsaKeys().getPublic();

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> CurvePoint.from(rsaPubKey, CurveSpec.C384));
    }

    @Test
    void from_WithPubKeyOnly_WithEcKey384_Success() throws KeystoreGenericException {
        // given
        final PublicKey ecPubKey = TestUtil.genEcKeys().getPublic();

        // when
        final CurvePoint curvePoint = CurvePoint.from(ecPubKey);

        // then
        Assertions.assertEquals(CurveSpec.C384, curvePoint.getCurveSpec());
    }

    @Test
    void from_WithPubKeyOnly_WithRsa_ThrowsException() throws KeystoreGenericException {
        // given
        final PublicKey rsaPubKey = TestUtil.genRsaKeys().getPublic();

        // when-then
        Assertions.assertThrows(IllegalArgumentException.class, () -> CurvePoint.from(rsaPubKey));
    }


    @Test
    void from_With48XY_WithPubKeyAndSpec_Success() {
        performTestWithPubKeyAndSpec(TestPublicKey.PUB_48XY);
    }

    @Test
    void from_With49X47Y_WithPubKeyAndSpec_Success() {
        performTestWithPubKeyAndSpec(TestPublicKey.PUB_49X47Y);
    }

    @Test
    void from_With48X49Y_WithPubKeyAndSpec_Success() {
        performTestWithPubKeyAndSpec(TestPublicKey.PUB_48X49Y);
    }

    @Test
    void from_With48XY_WithStringPointXAndY_Success() {
        performTestWithStringPoint(TestPublicKey.PUB_48XY);
    }

    @Test
    void from_With49X47Y_WithStringPointXAndY_Success() {
        performTestWithStringPoint(TestPublicKey.PUB_49X47Y);
    }

    @Test
    void from_With48X49Y_WithStringPointXAndY_Success() {
        performTestWithStringPoint(TestPublicKey.PUB_48X49Y);
    }

    @Test
    void from_With48X49Y_WithBytePointXY_ResultsWithSameXY() {
        // given
        byte[] pointX = fromHex(TestPublicKey.PUB_48X49Y.pointX);
        byte[] pointY = fromHex(TestPublicKey.PUB_48X49Y.pointY);

        // when
        final CurvePoint point = CurvePoint.from(pointX, pointY, CurveSpec.C384);

        // then
        Assertions.assertEquals(preparePoint(TestPublicKey.PUB_48X49Y.pointX), point.getHexPointA());
        Assertions.assertEquals(preparePoint(TestPublicKey.PUB_48X49Y.pointY), point.getHexPointB());
    }

    @Test
    void from_ByteBuffer_Success() {
        // given
        final String expected = prepareConcatenatedXY(TestPublicKey.PUB_49X47Y);

        // when
        final CurvePoint point = CurvePoint.from(ByteBufferSafe.wrap(fromHex(expected)), CurveSpec.C384);

        // then
        Assertions.assertEquals(expected, toHex(point.getAlignedDataToSize()));
    }

    @Test
    void fromPubKey_PlainXY_Success() {
        // given
        final String expected = prepareConcatenatedXY(TestPublicKey.PUB_49X47Y);

        // when
        final CurvePoint point = CurvePoint.fromPubKey(fromHex(expected), CurveSpec.C384);

        // then
        Assertions.assertEquals(expected, toHex(point.getAlignedDataToSize()));
    }

    @Test
    void fromPubKey_EncodedPubKey_Success() throws Exception {
        // given
        final String ecPubKeyEncoded = "3076301006072A8648CE3D020106052B8104002203620004703D168D760D6D8B60DB1CA4F08A0D0"
            + "29397C811F9F43AD407F9CC84A77910068B629A7E96E101E0EDEC541DA0A0EEDF156B840395010D7A06FFF37AEE5B226C4EC51E4"
            + "13E54BA719BB0308A12D4A1885FEE60BE1AD5C26D0417E70D56F25BB4";
        final String expectedA =
            "703D168D760D6D8B60DB1CA4F08A0D029397C811F9F43AD407F9CC84A77910068B629A7E96E101E0EDEC541DA0A0EEDF";
        final String expectedB =
            "156B840395010D7A06FFF37AEE5B226C4EC51E413E54BA719BB0308A12D4A1885FEE60BE1AD5C26D0417E70D56F25BB4";

        // when
        final CurvePoint point = CurvePoint.fromPubKeyEncoded(fromHex(ecPubKeyEncoded), CurveSpec.C384);

        // then
        Assertions.assertEquals(expectedA, point.getHexPointA());
        Assertions.assertEquals(expectedB, point.getHexPointB());
    }

    @Test
    void generateFingerprint_Success() {
        // given
        final String expected = prepareConcatenatedXY(TestPublicKey.PUB_49X47Y);
        final CurvePoint sut = CurvePoint.fromPubKey(fromHex(expected), CurveSpec.C384);

        // when
        final String fingerprint = sut.generateFingerprint();

        // then
        Assertions.assertEquals(
            "b7165c7217d4b65fbc2f4dfb7012174a7cf47cc4191738d1435835972cca69671fa4256b6b995603cb6712193a0b0638",
            fingerprint
        );
    }

    @Test
    void getAlignedDataToSize_With48XY_WithBytePointXY_ResultsWithAlignedToCurveSizeXY() {
        performTestAlignedData(TestPublicKey.PUB_48XY);
    }

    @Test
    void getAlignedDataToSize_With49X47Y_WithBytePointXY_ResultsWithAlignedToCurveSizeXY() {
        performTestAlignedData(TestPublicKey.PUB_49X47Y);
    }

    @Test
    void getAlignedDataToSize_With48X49Y_WithBytePointXY_ResultsWithAlignedToCurveSizeXY() {
        performTestAlignedData(TestPublicKey.PUB_48X49Y);
    }

    @Test
    void fromSignature_Success() throws Exception {
        // given
        final KeyPair ec384Keys = TestUtil.genEcKeys();
        final byte[] signature = EcUtils.signEcData(ec384Keys.getPrivate(), "test".getBytes(StandardCharsets.UTF_8),
            CryptoConstants.SHA384_WITH_ECDSA, CryptoUtils.getBouncyCastleProvider()
        );

        // then
        final CurvePoint curvePoint = CurvePoint.fromSignature(signature, () -> CurveSpec.C384);

        // Then
        Assertions.assertEquals(CurveSpec.C384, curvePoint.getCurveSpec());
    }

    @SneakyThrows
    private void performTestAlignedData(TestPublicKey testData) {
        // given
        final PublicKey publicKey = testData.getKey();
        final String expected = prepareConcatenatedXY(testData);

        // when
        final byte[] data = CurvePoint.from(publicKey, CurveSpec.C384).getAlignedDataToSize();

        // then
        Assertions.assertEquals(expected, toHex(data));
        Assertions.assertEquals(CurveSpec.C384.getSize() * 2, data.length);
    }

    private void performTestWithPubKeyAndSpec(TestPublicKey testData) {
        // given
        final PublicKey publicKey = testData.getKey();

        // when
        final CurvePoint point = CurvePoint.from(publicKey, CurveSpec.C384);

        // then
        Assertions.assertEquals(preparePoint(testData.pointX), toHex(point.getPointA()));
        Assertions.assertEquals(preparePoint(testData.pointY), toHex(point.getPointB()));
    }

    private void performTestWithStringPoint(TestPublicKey testData) {
        // when
        final CurvePoint point = CurvePoint.from(testData.pointX, testData.pointY, CurveSpec.C384);

        // then
        Assertions.assertEquals(preparePoint(testData.pointX), toHex(point.getPointA()));
        Assertions.assertEquals(preparePoint(testData.pointY), toHex(point.getPointB()));
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
