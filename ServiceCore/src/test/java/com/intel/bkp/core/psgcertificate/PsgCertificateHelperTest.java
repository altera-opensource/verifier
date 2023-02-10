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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.TestUtil;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateChainWrongSizeException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidLeafCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidParentCertificatesException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidRootCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKeyMagic;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.curve.EcSignatureAlgorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import static com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType.SECP256R1;
import static com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType.SECP384R1;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

class PsgCertificateHelperTest {

    private PsgCertificateHelper sut = new PsgCertificateHelper();

    @Test
    void getCertificateChainList_properlyParseCertificate() {
        // given
        String certChain = "klQJFwAAAQEAAAB4AAAAcQAAAAAAAAAAQGVmQwAAAGAAAAAAVDJmSAAAAAAAAAAAya2F1W0d3j9A\n"
            + "DJVlaI+eTxVZ3s/bo3DUqecSOuolIADT3kRuuXcUjxgTH0PLY9083YSjvQW3qnzRPAHxGy2rztM+\n"
            + "fsAcEEOlxDjtDsEuo3iyxZthzsp37GB3vwtqdZ1ydIgVIAAAADEAAAAwMFSIIACyX7rxh6JYJl1w\n"
            + "DD5CF1Yb82Y4nq+3XhxObBKX5AlXURKVnB1BcHEyCoj7oUJPi05zwUiFh3P4f/IOAUcTNGtsGz+b\n"
            + "EwcAKjvWpiKV3dMzhys+mm8SZtejGckyVioytO+JJZA2AAAAmAAAAIAAAAAAAAAAAAAAAAAAAAAA\n"
            + "AAAAAJMQURgAAAAwAAAAMFQyZkgAAAAAAAAAAPbj1fueGTJ+o+7059WPUiaeAug0Q09BxXIiunnN\n"
            + "pcqBXj95VWv75oZCW8JFxZ/I0AwWDUOBAXmogSc8SCNXe0NHJfjRSeGhT8lowHNttjsU1YUPn4ZU\n"
            + "nI05E6yfsZ0DNw==";
        // when
        List<CertificateEntryWrapper> certificateChainList = sut.getCertificateChainList(certChain);
        // then
        Assertions.assertEquals(2, certificateChainList.size());
        Assertions.assertEquals(PsgCertificateType.LEAF, certificateChainList.get(0).getType());
        Assertions.assertEquals(PsgCertificateType.ROOT, certificateChainList.get(1).getType());
    }

    @Test
    void getCertificateChainList_WithNoMagicNumbers_properlyParseCertificate() {
        // given
        String certChain = "6r6S8bSqOGWlG2s5Iaa=";
        // when
        List<CertificateEntryWrapper> certificateChainList = sut.getCertificateChainList(certChain);
        // then
        Assertions.assertEquals(0, certificateChainList.size());
    }

    @Test
    void verifyParentsInChainByPubKey_succeedsIfNoError() throws PsgInvalidParentCertificatesException,
        PsgCertificateException, PsgInvalidSignatureException {
        // given
        KeyPair rootKeyPair = TestUtil.genEcKeys(null);
        KeyPair leafKeyPair = TestUtil.genEcKeys(null);
        KeyPair leafSecondKeyPair = TestUtil.genEcKeys(null);

        assert rootKeyPair != null;
        assert leafKeyPair != null;
        assert leafSecondKeyPair != null;

        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();

        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));

        byte[] leafContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(PsgSignatureCurveType.SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .signData(dataToSign -> TestUtil.signEcData(
                dataToSign, rootKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA
            ), SECP384R1)
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        byte[] leafSecondContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(PsgSignatureCurveType.SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafSecondKeyPair, PsgCurveType.SECP384R1))
            .signData(dataToSign -> TestUtil.signEcData(
                dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA
            ), SECP384R1)
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafSecondContent));

        // when
        new PsgCertificateHelper().verifyParentsInChainByPubKey(certificateChainList);
    }

    @Test
    void verifyParentsInChainByPubKey_WithEc256_succeedsIfNoError()
        throws PsgInvalidParentCertificatesException, PsgCertificateException, PsgInvalidSignatureException {
        // given
        KeyPair rootKeyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_256);
        KeyPair leafKeyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_256);
        KeyPair leafSecondKeyPair = TestUtil.genEcKeys(CryptoConstants.EC_CURVE_SPEC_256);

        assert rootKeyPair != null;
        assert leafKeyPair != null;
        assert leafSecondKeyPair != null;

        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();

        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP256R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));

        byte[] leafContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(PsgSignatureCurveType.SECP256R1))
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP256R1))
            .signData(dataToSign -> TestUtil.signEcData(
                dataToSign, rootKeyPair.getPrivate(), CryptoConstants.SHA256_WITH_ECDSA
            ), SECP256R1)
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        byte[] leafSecondContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(PsgSignatureCurveType.SECP256R1))
            .publicKey(getPsgPublicKeyBuilder(leafSecondKeyPair, PsgCurveType.SECP256R1))
            .signData(dataToSign -> TestUtil.signEcData(
                dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA256_WITH_ECDSA
            ), SECP256R1)
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafSecondContent));

        // when
        new PsgCertificateHelper().verifyParentsInChainByPubKey(certificateChainList);
    }

    @Test
    void verifyParentsInChainByPubKey_withInvalidParent_throwException() throws PsgCertificateException {
        // given
        KeyPair rootKeyPair = TestUtil.genEcKeys(null);
        KeyPair leafKeyPair = TestUtil.genEcKeys(null);
        assert rootKeyPair != null;
        assert leafKeyPair != null;

        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();

        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));

        byte[] leafContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(PsgSignatureCurveType.SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .signData(dataToSign -> TestUtil.signEcData(
                dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA
            ), SECP384R1)
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        Assertions.assertThrows(PsgInvalidParentCertificatesException.class,
            () -> sut.verifyParentsInChainByPubKey(certificateChainList));
    }

    @Test
    void verifyParentsInChainByPubKey_withWrongSignature_throwException()
        throws PsgCertificateException, PsgInvalidSignatureException {
        MockitoAnnotations.openMocks(this);
        // given
        PsgCertificateHelper spy = Mockito.spy(sut);
        doThrow(new PsgInvalidSignatureException("Failed to check signature", new Exception()))
            .when(spy).sigVerify(any(), any());
        KeyPair rootKeyPair = TestUtil.genEcKeys(null);
        KeyPair leafKeyPair = TestUtil.genEcKeys(null);

        assert rootKeyPair != null;
        assert leafKeyPair != null;
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        byte[] leafContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(PsgSignatureCurveType.SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .signData(dataToSign -> TestUtil.signEcData(
                dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA
            ), SECP384R1)
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));

        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));

        // when
        Assertions.assertThrows(PsgInvalidSignatureException.class,
            () -> spy.verifyParentsInChainByPubKey(certificateChainList));
    }

    @Test
    void verifyChainListSize_withOneCertificate_throwsException() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));

        Assertions.assertThrows(PsgCertificateChainWrongSizeException.class,
            () -> sut.verifyChainListSizeInternal(certificateChainList));
    }

    @Test
    void verifyChainListSize_withFourCertificates_throwsException() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));

        Assertions.assertThrows(PsgCertificateChainWrongSizeException.class,
            () -> sut.verifyChainListSizeInternal(certificateChainList));
    }

    @Test
    void verifyChainListSizeInternal_withThreeCertificatesAndTwoRootCerts_throwsException() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));

        Assertions.assertThrows(PsgCertificateChainWrongSizeException.class,
            () -> sut.verifyChainListSizeInternal(certificateChainList));
    }

    @Test
    void verifyChainListSizeInternal_notThrowsAnything() throws PsgCertificateChainWrongSizeException {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, new byte[4]));

        // when
        sut.verifyChainListSizeInternal(certificateChainList);
    }

    @Test
    void verifyRootCertificateInternal_notThrowsAnything()
        throws PsgCertificateChainWrongSizeException, PsgInvalidRootCertificateException, PsgCertificateException {
        // given
        KeyPair rootKeyPair = TestUtil.genEcKeys(null);
        assert rootKeyPair != null;
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));

        // when
        sut.verifyRootCertificateInternal(certificateChainList, rootContent);

    }

    @Test
    void verifyRootCertificateInternal_withNoRootCert_throwsException() {
        // given
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[4]));

        Assertions.assertThrows(PsgCertificateChainWrongSizeException.class,
            () -> sut.verifyRootCertificateInternal(certificateChainList, new byte[4]));
    }

    @Test
    void verifyRootCertificateInternal_withIncorrectCert_throwsException() throws PsgCertificateException {
        // given
        KeyPair rootKeyPair = TestUtil.genEcKeys(null);
        KeyPair leafKeyPair = TestUtil.genEcKeys(null);
        assert rootKeyPair != null;
        assert leafKeyPair != null;
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        byte[] rootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(rootKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.ROOT, rootContent));
        byte[] wrongRootContent = new PsgCertificateRootEntryBuilder()
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .build()
            .array();

        Assertions.assertThrows(PsgInvalidRootCertificateException.class,
            () -> sut.verifyRootCertificateInternal(certificateChainList, wrongRootContent));
    }

    @Test
    void sigVerify_withPublicKey_Success() throws PsgInvalidSignatureException {
        // given
        KeyPair keyPair = TestUtil.genEcKeys();
        X509Certificate x509Certificate = TestUtil.genSelfSignedCert(keyPair);
        byte[] testData = "TestDataToSignAndVerify".getBytes();
        byte[] signed = TestUtil.signEcData(testData, keyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA);
        PsgSignatureBuilder psgSignature = new PsgSignatureBuilder().signature(signed, SECP384R1);

        // when
        boolean verify = PsgCertificateHelper.sigVerify(
            EcSignatureAlgorithm.ECDSA_P384, x509Certificate.getPublicKey(), testData, psgSignature.getCurvePoint()
        );

        // then
        Assertions.assertTrue(verify);
    }

    @Test
    void sigVerify_withInvalidCertificateOrder_ReturnsFalse() throws PsgInvalidSignatureException {
        // given
        PsgCertificateCommon child = Mockito.mock(PsgCertificateCommon.class);
        PsgCertificateCommon parent = Mockito.mock(PsgCertificateCommon.class);
        PsgCertificateHelper spy = Mockito.spy(sut);

        // when
        boolean result = spy.sigVerify(child, parent);

        // then
        Assertions.assertFalse(result);
    }

    @Test
    void parseRootCertificate_ThrowsException() {
        Assertions.assertThrows(PsgInvalidRootCertificateException.class, () -> sut.parseRootCertificate(new byte[4]));
    }

    @Test
    void findLeafCertificateInChain_Success()
        throws PsgCertificateChainWrongSizeException, PsgInvalidLeafCertificateException, PsgCertificateException {
        // given
        KeyPair leafKeyPair = TestUtil.genEcKeys(null);
        KeyPair leafKeyPairSecond = TestUtil.genEcKeys(null);

        assert leafKeyPair != null;
        assert leafKeyPairSecond != null;
        List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        byte[] leafContent = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(PsgSignatureCurveType.SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafKeyPair, PsgCurveType.SECP384R1))
            .signData(dataToSign -> TestUtil.signEcData(
                dataToSign, leafKeyPair.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA
            ), SECP384R1)
            .build()
            .array();
        PsgCertificateEntry leafContentSecond = new PsgCertificateEntryBuilder()
            .withSignature(getPsgSignatureBuilder(PsgSignatureCurveType.SECP384R1))
            .publicKey(getPsgPublicKeyBuilder(leafKeyPairSecond, PsgCurveType.SECP384R1))
            .signData(dataToSign -> TestUtil.signEcData(
                dataToSign, leafKeyPairSecond.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA
            ), SECP384R1)
            .build();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContent));
        certificateChainList
            .add(new CertificateEntryWrapper(PsgCertificateType.LEAF, leafContentSecond.array()));

        // when
        final PsgCertificateEntryBuilder leafCertificateInChain = sut.findLeafCertificateInChain(certificateChainList);

        // then
        Assertions.assertArrayEquals(leafContentSecond.array(), leafCertificateInChain.build().array());
    }

    @Test
    void findLeafCertificateInChain_WithEmptyArray_ThrowsException() {
        // then
        Assertions.assertThrows(PsgCertificateChainWrongSizeException.class,
            () -> sut.findLeafCertificateInChain(new LinkedList<>()));
    }

    @Test
    void findLeafCertificateInChain_WithWrongCertificate_ThrowsException() {
        // given
        final List<CertificateEntryWrapper> certificateChainList = new LinkedList<>();
        certificateChainList.add(new CertificateEntryWrapper(PsgCertificateType.LEAF, new byte[5]));

        Assertions.assertThrows(PsgInvalidLeafCertificateException.class,
            () -> sut.findLeafCertificateInChain(certificateChainList));
    }

    private PsgPublicKeyBuilder getPsgPublicKeyBuilder(KeyPair keyPair, PsgCurveType psgCurveType) {
        return new PsgPublicKeyBuilder()
            .magic(PsgPublicKeyMagic.M1_MAGIC)
            .publicKey(keyPair.getPublic(), psgCurveType);
    }

    private PsgSignatureBuilder getPsgSignatureBuilder(PsgSignatureCurveType psgSignatureCurveType) {
        return PsgSignatureBuilder.empty(psgSignatureCurveType);
    }
}
