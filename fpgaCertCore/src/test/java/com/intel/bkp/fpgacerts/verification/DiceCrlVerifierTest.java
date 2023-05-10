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

package com.intel.bkp.fpgacerts.verification;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoExtensionParser;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jce.provider.X509CRLEntryObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import static com.intel.bkp.crypto.x509.utils.X509ExtensionUtils.getExtensionBytes;
import static com.intel.bkp.fpgacerts.Utils.readCertificate;
import static com.intel.bkp.fpgacerts.dice.tcbinfo.verification.TcbInfoTestUtil.parseTcbInfo;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_MULTI_TCB_INFO;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_TCB_INFO;
import static com.intel.bkp.fpgacerts.verification.CrlVerifier.SERIAL_NUMBER_REVOCATION_REASON;
import static com.intel.bkp.fpgacerts.verification.DiceCrlVerifier.TCB_INFO_REVOCATION_REASON;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static java.math.BigInteger.TWO;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiceCrlVerifierTest {

    public static final ASN1ObjectIdentifier TCB_INFO_EXTENSION_OID =
        new ASN1ObjectIdentifier(TCG_DICE_TCB_INFO.getOid());
    public static final ASN1ObjectIdentifier MULTI_TCB_INFO_EXTENSION_OID =
        new ASN1ObjectIdentifier(TCG_DICE_MULTI_TCB_INFO.getOid());
    public static final byte[] TCB_INFO_WITH_ONLY_FW_ID = fromHex(
        "302B800676656E646F7281056D6F64656C820776657273696F6E830100840100850100A608300606012A040100");
    public static final byte[] TCB_INFO_WITH_FW_ID_AND_VENDOR_INFO = fromHex(
        "302E800676656E646F7281056D6F64656C820776657273696F6E830100840100850100A608300606012A040100880100");
    public static final byte[] TCB_INFO_WITH_VENDOR_INFO_1234 = fromHex(
        "301C800676656E646F7281056D6F64656C83010084010085010088021234");
    public static final byte[] TCB_INFO_WITH_VENDOR_INFO_12 = fromHex(
        "301B800676656E646F7281056D6F64656C830100840100850100880112");
    private static X509Certificate singleTcbInfoCert;
    private static byte[] singleTcbInfoFromCert;
    private static X509Certificate multiTcbInfoCert;
    private static byte[] multiTcbInfoFromCert;
    private static byte[] firstTcbInfoFromMultiTcbInfoFromCert;
    private static byte[] secondTcbInfoFromMultiTcbInfoFromCert;

    private static MockedStatic<TcbInfoExtensionParser> tcbInfoExtensionParserMockedStatic;

    @Mock(answer = Answers.CALLS_REAL_METHODS)
    private TcbInfoExtensionParser tcbInfoExtParser;

    @Mock
    private X509CRLEntry crlEntry;

    @Mock
    private X509CRL crl;

    @InjectMocks
    private DiceCrlVerifier sut;

    @BeforeAll
    static void prepareStaticMock() {
        tcbInfoExtensionParserMockedStatic = mockStatic(TcbInfoExtensionParser.class, CALLS_REAL_METHODS);
    }

    @AfterAll
    public static void closeStaticMock() {
        tcbInfoExtensionParserMockedStatic.close();
    }

    @BeforeAll
    static void loadCerts() throws Exception {
        singleTcbInfoCert = readCertificate("certs/dice/aliasEfuseChain/",
            "deviceid_08cbe74ddca0b53a_7eukZEEF-nzSZWoHQrqQf53ru9A.cer");
        singleTcbInfoFromCert = getExtensionBytes(singleTcbInfoCert, TCB_INFO_EXTENSION_OID).orElseThrow();
        multiTcbInfoCert = readCertificate("certs/dice/aliasEfuseSpdmChain/",
            "deviceId_01458210996be470_spdm.cer");
        multiTcbInfoFromCert = getExtensionBytes(multiTcbInfoCert, MULTI_TCB_INFO_EXTENSION_OID).orElseThrow();
        final List<byte[]> tcbInfosFromMultiTcbInfo = getTcbInfosFromMultiTcbInfo();
        firstTcbInfoFromMultiTcbInfoFromCert = tcbInfosFromMultiTcbInfo.get(0);
        secondTcbInfoFromMultiTcbInfoFromCert = tcbInfosFromMultiTcbInfo.get(1);
    }

    private static List<byte[]> getTcbInfosFromMultiTcbInfo() {
        return Arrays.stream(DLSequence.getInstance(multiTcbInfoFromCert).toArray())
            .map(ASN1Encodable::toASN1Primitive)
            .map(getBytes())
            .toList();
    }

    private static Function<ASN1Primitive, byte[]> getBytes() {
        return asn1Primitive -> {
            try {
                return asn1Primitive.getEncoded();
            } catch (IOException e) {
                return null;
            }
        };
    }

    @SneakyThrows
    private static byte[] prepareMultiTcbInfo(byte[]... tcbInfos) {
        final ASN1EncodableVector v = new ASN1EncodableVector();
        for (final byte[] tcbInfo : tcbInfos) {
            v.add(DLSequence.getInstance(tcbInfo));
        }

        return new DERSequence(v).getEncoded();
    }

    private X509CRLEntryObject createX509CRLEntry(BigInteger serialNumber) {
        return createX509CRLEntry(serialNumber, Optional.empty());
    }

    private X509CRLEntryObject createX509CRLEntryWithTcbInfo(byte[] tcbInfoSequenceBytes) {
        return createX509CRLEntryWithTcbInfo(TWO, TCB_INFO_EXTENSION_OID, tcbInfoSequenceBytes);
    }

    private X509CRLEntryObject createX509CRLEntryWithMultiTcbInfo(byte[] multiTcbInfoSequenceBytes) {
        return createX509CRLEntryWithTcbInfo(TWO, MULTI_TCB_INFO_EXTENSION_OID, multiTcbInfoSequenceBytes);
    }

    private X509CRLEntryObject createX509CRLEntryWithTcbInfo(BigInteger serialNumber, ASN1ObjectIdentifier oid,
                                                             byte[] tcbInfoSequenceBytes) {
        final Extension tcbInfoExtension = new Extension(oid, true, tcbInfoSequenceBytes);
        return createX509CRLEntry(serialNumber, Optional.of(new Extensions(tcbInfoExtension)));
    }

    private X509CRLEntryObject createX509CRLEntry(BigInteger serialNumber, Optional<Extensions> extensions) {
        final ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(serialNumber));
        v.add(new Time(new Date()));
        extensions.ifPresent(v::add);

        return new X509CRLEntryObject(
            TBSCertList.CRLEntry.getInstance(
                new DERSequence(v)));
    }

    @SuppressWarnings("unchecked")
    private void mockCrlEntries(Set entries) {
        when(crl.getRevokedCertificates()).thenReturn(entries);
    }

    private X509Certificate prepareMockedCert(byte[] tcbInfoSequence) {
        final var cert = mock(X509Certificate.class);
        when(TcbInfoExtensionParser.containsTcbInfoExtension(cert)).thenReturn(true);
        when(tcbInfoExtParser.parse(cert)).thenReturn(List.of(parseTcbInfo(tcbInfoSequence)));
        return cert;
    }

    @Nested
    class RevokedBySerialNumberTestCases {

        @Test
        void getRevocationReason_MatchingSn() {
            // given
            final var cert = singleTcbInfoCert;
            final var certSn = cert.getSerialNumber();
            when(crlEntry.getSerialNumber()).thenReturn(certSn);
            mockCrlEntries(Set.of(crlEntry));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isPresent());
            assertEquals(SERIAL_NUMBER_REVOCATION_REASON, reason.get());
        }

        @Test
        void getRevocationReason_MatchingSnAndTcbInfo() {
            // given
            final var cert = singleTcbInfoCert;
            final var certSn = cert.getSerialNumber();
            final var crlEntryWithSn = createX509CRLEntry(certSn);
            final var crlEntryWithTcbInfo = createX509CRLEntryWithTcbInfo(singleTcbInfoFromCert);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo, crlEntryWithSn));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isPresent());
            assertEquals(SERIAL_NUMBER_REVOCATION_REASON, reason.get());
        }
    }

    @Nested
    class RevokedByTcbInfoTestCases {

        @Test
        void getRevocationReason_SingleTcbInfoIdenticalToCert() {
            // given
            final var cert = singleTcbInfoCert;
            final var crlEntryWithTcbInfo = createX509CRLEntryWithTcbInfo(singleTcbInfoFromCert);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isPresent());
            assertEquals(TCB_INFO_REVOCATION_REASON, reason.get());
        }

        @Test
        void getRevocationReason_SingleTcbInfoWithLessValueFieldsThanInCert() {
            // given
            final var cert = prepareMockedCert(TCB_INFO_WITH_FW_ID_AND_VENDOR_INFO);

            final var crlEntryWithTcbInfo = createX509CRLEntryWithTcbInfo(TCB_INFO_WITH_ONLY_FW_ID);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isPresent());
            assertEquals(TCB_INFO_REVOCATION_REASON, reason.get());
        }

        @Test
        void getRevocationReason_MultiTcbInfoWithOnlySingleTcbInfoFromCert() {
            // given
            final var cert = singleTcbInfoCert;
            final var multiTcbInfoWithOnlyOneTcbInfo = prepareMultiTcbInfo(singleTcbInfoFromCert);
            final var crlEntryWithTcbInfo = createX509CRLEntryWithMultiTcbInfo(multiTcbInfoWithOnlyOneTcbInfo);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isPresent());
            assertEquals(TCB_INFO_REVOCATION_REASON, reason.get());
        }

        @Test
        void getRevocationReason_MultiTcbInfoIdenticalToCert() {
            // given
            final var cert = multiTcbInfoCert;
            final var crlEntryWithTcbInfo = createX509CRLEntryWithMultiTcbInfo(multiTcbInfoFromCert);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isPresent());
            assertEquals(TCB_INFO_REVOCATION_REASON, reason.get());
        }

        @Test
        void getRevocationReason_SingleTcbInfoMatchingOneTcbInfoFromMultiTcbInfo() {
            // given
            final var cert = multiTcbInfoCert;
            final var crlEntryWithTcbInfo = createX509CRLEntryWithTcbInfo(secondTcbInfoFromMultiTcbInfoFromCert);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isPresent());
            assertEquals(TCB_INFO_REVOCATION_REASON, reason.get());
        }

        @Test
        void getRevocationReason_SingleTcbInfoWithVendorInfoShorterThanInCert() {
            // given
            final var cert = prepareMockedCert(TCB_INFO_WITH_VENDOR_INFO_1234);

            final var crlEntryWithTcbInfo = createX509CRLEntryWithTcbInfo(TCB_INFO_WITH_VENDOR_INFO_12);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isPresent());
            assertEquals(TCB_INFO_REVOCATION_REASON, reason.get());
        }
    }

    @Nested
    class NotRevokedTestCases {

        @Test
        void getRevocationReason_NoCrlEntries() {
            // given
            mockCrlEntries(Set.of());

            // when
            final var reason = sut.getRevocationReason(crl, singleTcbInfoCert);

            // then
            assertTrue(reason.isEmpty());
        }

        @Test
        void getRevocationReason_MatchingSnInCrlEntryWithTcbInfo() {
            // given
            final var cert = singleTcbInfoCert;
            final var certSn = cert.getSerialNumber();
            final var crlEntryWithTcbInfo =
                createX509CRLEntryWithTcbInfo(certSn, TCB_INFO_EXTENSION_OID, firstTcbInfoFromMultiTcbInfoFromCert);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isEmpty());
        }

        @Test
        void getRevocationReason_SingleTcbInfoWithMoreValueFieldsThanInCert() {
            // given
            final var cert = prepareMockedCert(TCB_INFO_WITH_ONLY_FW_ID);

            final var crlEntryWithTcbInfo = createX509CRLEntryWithTcbInfo(TCB_INFO_WITH_FW_ID_AND_VENDOR_INFO);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isEmpty());
        }

        @Test
        void getRevocationReason_SingleTcbInfoWithVendorInfoLongerThanInCert() {
            // given
            final var cert = prepareMockedCert(TCB_INFO_WITH_VENDOR_INFO_12);

            final var crlEntryWithTcbInfo = createX509CRLEntryWithTcbInfo(TCB_INFO_WITH_VENDOR_INFO_1234);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isEmpty());
        }

        @Test
        void getRevocationReason_MultiTcbInfoInCrlEntryContainsOneMoreTcbInfoThanCert() {
            // given
            final var cert = singleTcbInfoCert;
            final var multiTcbInfoWithOneAdditionalTcbInfo =
                prepareMultiTcbInfo(singleTcbInfoFromCert, firstTcbInfoFromMultiTcbInfoFromCert);
            final var crlEntryWithTcbInfo =
                createX509CRLEntryWithMultiTcbInfo(multiTcbInfoWithOneAdditionalTcbInfo);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isEmpty());
        }

        @Test
        void getRevocationReason_MultiTcbInfoInCrlEntryContainsOneMatchingAndOneDifferentTcbInfoThanCert() {
            // given
            final var cert = multiTcbInfoCert;
            final var multiTcbInfoWithOneMatchingAndOneDifferentTcbInfo =
                prepareMultiTcbInfo(firstTcbInfoFromMultiTcbInfoFromCert, singleTcbInfoFromCert);
            final var crlEntryWithTcbInfo =
                createX509CRLEntryWithMultiTcbInfo(multiTcbInfoWithOneMatchingAndOneDifferentTcbInfo);
            mockCrlEntries(Set.of(crlEntryWithTcbInfo));

            // when
            final var reason = sut.getRevocationReason(crl, cert);

            // then
            assertTrue(reason.isEmpty());
        }
    }
}
