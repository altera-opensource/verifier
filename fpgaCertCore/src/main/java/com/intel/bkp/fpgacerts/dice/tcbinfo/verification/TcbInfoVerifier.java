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

package com.intel.bkp.fpgacerts.dice.tcbinfo.verification;

import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateSubject;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoAggregator;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoExtensionParser;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.containsExtension;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_MULTI_TCB_INFO;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_TCB_INFO;
import static com.intel.bkp.utils.ListUtils.toLinkedList;


@Slf4j
public class TcbInfoVerifier {

    private final ModelVerifier modelVerifier;
    private final TcbInfoExtensionParser extensionParser;
    private final TcbInfoAggregator aggregator;
    private final RequiredMeasurementsExistenceVerifier requiredMeasurementsExistenceVerifier;
    private final List<ITcbInfoFieldVerifier> fieldVerifiers;

    private LinkedList<X509Certificate> certificates = new LinkedList<>();

    public TcbInfoVerifier() {
        this(new TcbInfoAggregator(),
            new TcbInfoExtensionParser(),
            new RequiredMeasurementsExistenceVerifier(),
            new ModelVerifier(),
            new VendorVerifier(),
            new SvnVerifier(),
            new LayerVerifier(),
            new HashAlgVerifier(),
            new TypeVerifier(),
            new FlagsVerifier());
    }

    public TcbInfoVerifier(TcbInfoAggregator aggregator, TcbInfoExtensionParser extensionParser,
                           RequiredMeasurementsExistenceVerifier requiredMeasurementsExistenceVerifier,
                           ModelVerifier modelVerifier, ITcbInfoFieldVerifier... verifiers) {
        this.aggregator = aggregator;
        this.extensionParser = extensionParser;
        this.requiredMeasurementsExistenceVerifier = requiredMeasurementsExistenceVerifier;
        this.modelVerifier = modelVerifier;

        List<ITcbInfoFieldVerifier> mutableList = new ArrayList<>(Arrays.asList(verifiers));
        mutableList.add(modelVerifier);
        this.fieldVerifiers = List.copyOf(mutableList);
    }

    public TcbInfoVerifier certificates(List<X509Certificate> certificates) {
        this.certificates = toLinkedList(certificates);
        this.aggregator.getMap().clear();
        return this;
    }

    public boolean verify() {
        if (certificates.isEmpty()) {
            return false;
        }

        try {
            return verifyInternal();
        } catch (Exception e) {
            log.error("Failed to verify TcbInfo in chain, unexpected error occurred.", e);
            return false;
        }
    }

    private boolean verifyInternal() {
        final var familyName = getFamilyName(certificates.getFirst());
        modelVerifier.withFamilyName(familyName);
        return verifyAllTcbInfosAreValid() && verifyAllRequiredMeasurementsExistInChain(familyName);
    }

    private String getFamilyName(X509Certificate certificate) {
        return DiceCertificateSubject.parse(certificate.getSubjectDN().getName()).getFamilyName();
    }

    private boolean verifyAllTcbInfosAreValid() {
        return certificates.stream().allMatch(this::verifyCertificate);
    }

    private boolean verifyAllRequiredMeasurementsExistInChain(String familyName) {
        return requiredMeasurementsExistenceVerifier
            .withFamilyName(familyName)
            .verify(aggregator.getMap());
    }

    public boolean verifyCertificate(final X509Certificate certificate) {
        if (!containsTcbInfoExtension(certificate)) {
            log.debug("Certificate does not contain TcbInfo extension: {}", certificate.getSubjectDN());
            return true;
        }

        final List<TcbInfo> tcbInfos = getTcbInfosFromCertificate(certificate);
        final boolean valid = verifyAllTcbInfosHaveCorrectFields(tcbInfos)
            && verifyThereAreNoDifferentValuesForGivenTcbInfoKeyInChain(tcbInfos);

        if (!valid) {
            log.error("Certificate has invalid TcbInfo extension value: {}", certificate.getSubjectDN());
        }

        return valid;
    }

    private boolean containsTcbInfoExtension(final X509Certificate certificate) {
        final var tcbInfoOid = new ASN1ObjectIdentifier(TCG_DICE_TCB_INFO.getOid());
        final var multiTcbInfoOid = new ASN1ObjectIdentifier(TCG_DICE_MULTI_TCB_INFO.getOid());
        return containsExtension(certificate, tcbInfoOid) || containsExtension(certificate, multiTcbInfoOid);
    }

    private List<TcbInfo> getTcbInfosFromCertificate(final X509Certificate certificate) {
        return extensionParser.parse(certificate);
    }

    private boolean verifyThereAreNoDifferentValuesForGivenTcbInfoKeyInChain(List<TcbInfo> tcbInfos) {
        try {
            aggregator.add(tcbInfos);
            return true;
        } catch (IllegalArgumentException e) {
            log.error(e.getMessage());
            return false;
        }
    }

    private boolean verifyAllTcbInfosHaveCorrectFields(List<TcbInfo> tcbInfos) {
        return tcbInfos.stream()
            .allMatch(this::verifyTcbInfoFields);
    }

    private boolean verifyTcbInfoFields(TcbInfo tcbInfo) {
        try {
            return fieldVerifiers.stream().allMatch(fieldVerifier -> fieldVerifier.verify(tcbInfo));
        } catch (Exception e) {
            log.error("Failed to verify TcbInfo value, unexpected exception occured.", e);
            return false;
        }
    }

}
