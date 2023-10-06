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

package com.intel.bkp.fpgacerts.dice.tcbinfo.verification;

import com.intel.bkp.fpgacerts.dice.iidutils.IidUdsChainUtils;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoExtensionParser;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoMeasurementsAggregator;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.DEROctetString;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.lang.reflect.Field;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_TCB_INFO;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TcbInfoVerifierTest {

    private static final String FAMILY_NAME = "Agilex";
    private static final String TCBINFO_WITH_ROM_EXT_HASH_LAYER =
        "305D8009696E74656C2E636F6D81064167696C6578830105840100850100A63F303D06096086480165030402020430FF01020304050607"
            + "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F";
    private static final String TCBINFO_WITH_CMF_HASH_LAYER =
        "305D8009696E74656C2E636F6D81064167696C6578830105840101850100A63F303D06096086480165030402020430FF01020304050607"
            + "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F";
    private static final String TCBINFO_WITH_CMF_HASH_LAYER_DIFFERENT_DIGEST =
        "305D8009696E74656C2E636F6D81064167696C6578830105840101850100A63F303D060960864801650304020204300000000000000000"
            + "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
    private static final String TCBINFO_WITH_LAYER_2 =
        "305D8009696E74656C2E636F6D81064167696C6578830105840102850100A63F303D06096086480165030402020430FF01020304050607"
            + "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F";

    private static MockedStatic<IidUdsChainUtils> iidUdsChainUtilsMockedStatic;

    @Mock
    private X509Certificate childCertificate;

    @Mock
    private X509Certificate parentCertificate;

    @Mock
    private X509Certificate rootCertificate;

    @Mock
    private RequiredMeasurementsExistenceVerifier requiredMeasurementsVerifier;

    @Mock
    private ModelVerifier modelVerifier;

    @Mock
    private VendorVerifier vendorVerifier;

    @Mock
    private SvnVerifier svnVerifier;

    @Mock
    private LayerVerifier layerVerifier;

    @Mock
    private HashAlgVerifier hashAlgVerifier;

    @Mock
    private TypeVerifier typeVerifier;

    @Mock
    private FlagsVerifier flagsVerifier;

    private TcbInfoMeasurementsAggregator aggregator;

    private TcbInfoVerifier sut;

    @BeforeAll
    public static void prepareStaticMock() {
        iidUdsChainUtilsMockedStatic = mockStatic(IidUdsChainUtils.class);
    }

    @AfterAll
    public static void closeStaticMock() {
        iidUdsChainUtilsMockedStatic.close();
    }

    @BeforeEach
    void init() {
        aggregator = new TcbInfoMeasurementsAggregator();
        sut = new TcbInfoVerifier(aggregator, new TcbInfoExtensionParser(), requiredMeasurementsVerifier,
            modelVerifier, vendorVerifier, svnVerifier, layerVerifier, hashAlgVerifier, typeVerifier, flagsVerifier);
    }

    @SuppressWarnings("unchecked")
    @Test
    void defaultConstructor_containsAllFieldVerifiers() {
        // given
        final var expectedFieldVerifierClasses = List.of(
            ModelVerifier.class,
            VendorVerifier.class,
            SvnVerifier.class,
            LayerVerifier.class,
            HashAlgVerifier.class,
            TypeVerifier.class,
            FlagsVerifier.class);

        // when
        final var tcbInfoVerifier = new TcbInfoVerifier(false);

        // then
        final var actualFieldVerifierClasses =
            ((List<ITcbInfoFieldVerifier>) getPrivateFieldValue("fieldVerifiers", tcbInfoVerifier)).stream()
                .map(ITcbInfoFieldVerifier::getClass)
                .toList();

        assertEquals(expectedFieldVerifierClasses.size(), actualFieldVerifierClasses.size());
        assertTrue(expectedFieldVerifierClasses.containsAll(actualFieldVerifierClasses));
    }

    @Test
    void defaultConstructor_passesTestModeSecretsToFlagsVerifier() {
        // when
        final var tcbInfoVerifierWithTestModeSecretsTrue = new TcbInfoVerifier(true);
        final var tcbInfoVerifierWithTestModeSecretsFalse = new TcbInfoVerifier(false);

        // then
        verifyTestModeSecretsInFlagsVerifier(true, tcbInfoVerifierWithTestModeSecretsTrue);
        verifyTestModeSecretsInFlagsVerifier(false, tcbInfoVerifierWithTestModeSecretsFalse);
    }

    @Test
    void verify_CorrectChain_Success() {
        // given
        final var chain = List.of(childCertificate, parentCertificate, rootCertificate);
        final int tcbInfosInChain = 3;
        mockFamilyName();
        mockTcbInfoExtension(childCertificate, TCBINFO_WITH_CMF_HASH_LAYER);
        mockTcbInfoExtension(parentCertificate, TCBINFO_WITH_ROM_EXT_HASH_LAYER);
        mockTcbInfoExtension(rootCertificate, TCBINFO_WITH_LAYER_2);
        mockAllFieldsVerifiersToPassValidation();
        mockRequiredMeasurementsExistenceVerifier(true);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        assertTrue(result);
        verify(modelVerifier).withFamilyName(FAMILY_NAME);
        verify(modelVerifier, times(tcbInfosInChain)).verify(any());
        verify(vendorVerifier, times(tcbInfosInChain)).verify(any());
        verify(layerVerifier, times(tcbInfosInChain)).verify(any());
        verify(hashAlgVerifier, times(tcbInfosInChain)).verify(any());
        verify(flagsVerifier, times(tcbInfosInChain)).verify(any());
    }

    @Test
    void verify_NotAllRequiredMeasurements_Fails() {
        // given
        final var chain = List.of(childCertificate, parentCertificate);
        mockFamilyName();
        mockTcbInfoExtension(childCertificate, TCBINFO_WITH_CMF_HASH_LAYER);
        mockAllFieldsVerifiersToPassValidation();
        mockRequiredMeasurementsExistenceVerifier(false);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        assertFalse(result);
    }

    @Test
    void verify_NotAllRequiredMeasurements_IidUdsChain_Success() {
        // given
        final var chain = List.of(childCertificate, parentCertificate);
        mockFamilyName();
        mockTcbInfoExtension(childCertificate, TCBINFO_WITH_CMF_HASH_LAYER);
        mockAllFieldsVerifiersToPassValidation();
        mockIsIidUdsChain(chain);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        assertTrue(result);
    }

    @Test
    void verify_OneCertWithoutTcbInfo_Success() {
        // given
        final var chain = List.of(childCertificate, parentCertificate, rootCertificate);
        mockFamilyName();
        mockTcbInfoExtension(childCertificate, TCBINFO_WITH_CMF_HASH_LAYER);
        mockTcbInfoExtension(parentCertificate, TCBINFO_WITH_ROM_EXT_HASH_LAYER);
        mockAllFieldsVerifiersToPassValidation();
        mockRequiredMeasurementsExistenceVerifier(true);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        assertTrue(result);
    }

    @Test
    void verify_EmptyChain_Fails() {
        // given
        final var emptyChain = new LinkedList<X509Certificate>();

        // when
        final boolean result = sut.certificates(emptyChain).verify();

        // then
        assertFalse(result);
    }

    @Test
    void verify_LeafCertWithIncorrectSubjectFormat_Fails() {
        // given
        final var chain = List.of(childCertificate, parentCertificate, rootCertificate);
        mockSubject("CN=Not a correct DICE subject", childCertificate);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        assertFalse(result);
    }

    @Test
    void verify_OneOfFieldsIsIncorrect_Fails() {
        // given
        final var chain = List.of(childCertificate, parentCertificate, rootCertificate);
        mockFamilyName();
        mockTcbInfoExtension(childCertificate, TCBINFO_WITH_CMF_HASH_LAYER);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        assertFalse(result);
    }

    @Test
    void verify_OneOfFieldsCantBeVerified_Fails() {
        // given
        final var chain = List.of(childCertificate, parentCertificate, rootCertificate);
        mockFamilyName();
        mockTcbInfoExtension(childCertificate, TCBINFO_WITH_CMF_HASH_LAYER);
        mockOneOfFieldVerifiersToThrow();

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        assertFalse(result);
    }

    @Test
    void verify_DifferentValuesForTheSameTcbInfoKey_Fails() {
        // given
        final var chain = List.of(childCertificate, parentCertificate, rootCertificate);
        mockFamilyName();
        mockTcbInfoExtension(childCertificate, TCBINFO_WITH_ROM_EXT_HASH_LAYER);
        mockTcbInfoExtension(parentCertificate, TCBINFO_WITH_CMF_HASH_LAYER);
        mockTcbInfoExtension(rootCertificate, TCBINFO_WITH_CMF_HASH_LAYER_DIFFERENT_DIGEST);
        mockAllFieldsVerifiersToPassValidation();

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        assertFalse(result);
    }

    @Test
    void verify_IdenticalValuesForTheSameTcbInfoKey_Success() {
        // given
        final var chain = List.of(childCertificate, parentCertificate, rootCertificate);
        mockFamilyName();
        mockTcbInfoExtension(childCertificate, TCBINFO_WITH_ROM_EXT_HASH_LAYER);
        mockTcbInfoExtension(parentCertificate, TCBINFO_WITH_CMF_HASH_LAYER);
        mockTcbInfoExtension(rootCertificate, TCBINFO_WITH_CMF_HASH_LAYER);
        mockAllFieldsVerifiersToPassValidation();
        mockRequiredMeasurementsExistenceVerifier(true);

        // when
        final boolean result = sut.certificates(chain).verify();

        // then
        assertTrue(result);
    }

    private void mockFamilyName() {
        final String subject = String.format("CN=Intel:%s:L0:DW43eBZHek7h0vG3:0123456789abcdef", FAMILY_NAME);
        mockSubject(subject, childCertificate);
        when(modelVerifier.withFamilyName(any())).thenReturn(modelVerifier);
    }

    private void mockSubject(String subject, X509Certificate certificate) {
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal(subject));
    }

    private void mockRequiredMeasurementsExistenceVerifier(boolean allRequiredMeasurementsExist) {
        when(requiredMeasurementsVerifier.withFamilyName(FAMILY_NAME)).thenReturn(requiredMeasurementsVerifier);
        when(requiredMeasurementsVerifier.verify(aggregator.getMap())).thenReturn(allRequiredMeasurementsExist);
    }

    private void mockAllFieldsVerifiersToPassValidation() {
        when(modelVerifier.verify(any())).thenReturn(true);
        when(vendorVerifier.verify(any())).thenReturn(true);
        when(svnVerifier.verify(any())).thenReturn(true);
        when(layerVerifier.verify(any())).thenReturn(true);
        when(hashAlgVerifier.verify(any())).thenReturn(true);
        when(typeVerifier.verify(any())).thenReturn(true);
        when(flagsVerifier.verify(any())).thenReturn(true);
    }

    private void mockOneOfFieldVerifiersToThrow() {
        mockAllFieldsVerifiersToPassValidation();
        when(modelVerifier.verify(any())).thenThrow(new RuntimeException());
    }

    @SneakyThrows
    private void mockTcbInfoExtension(X509Certificate certificate, String tcbInfoSequenceInHex) {
        final var extensionValue = new DEROctetString(fromHex(tcbInfoSequenceInHex)).getEncoded();
        when(certificate.getCriticalExtensionOIDs()).thenReturn(Set.of(TCG_DICE_TCB_INFO.getOid()));
        when(certificate.getExtensionValue(TCG_DICE_TCB_INFO.getOid())).thenReturn(extensionValue);
    }

    @SuppressWarnings("unchecked")
    @SneakyThrows
    private void verifyTestModeSecretsInFlagsVerifier(boolean expectedTestModeSecrets,
                                                      TcbInfoVerifier tcbInfoVerifier) {
        final var flagsVerifier =
            ((List<ITcbInfoFieldVerifier>) getPrivateFieldValue("fieldVerifiers", tcbInfoVerifier)).stream()
                .filter(v -> v.getClass().equals(FlagsVerifier.class))
                .findAny()
                .get();

        final boolean actualTestModeSecrets = (boolean) getPrivateFieldValue("testModeSecrets", flagsVerifier);
        assertEquals(expectedTestModeSecrets, actualTestModeSecrets);
    }

    @SneakyThrows
    private Object getPrivateFieldValue(String fieldName, Object obj) {
        final Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    private void mockIsIidUdsChain(List<X509Certificate> chain) {
        when(IidUdsChainUtils.isIidUdsChain(chain)).thenReturn(true);
    }
}
