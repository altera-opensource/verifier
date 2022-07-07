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

package com.intel.bkp.fpgacerts.dice.subject;

import com.intel.bkp.fpgacerts.exceptions.InvalidDiceCertificateSubjectException;
import com.intel.bkp.fpgacerts.exceptions.UnknownFamilyIdException;
import com.intel.bkp.fpgacerts.model.AttFamily;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.containsExtension;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_UEID;

@Slf4j
public class DiceSubjectVerifier {

    private List<X509Certificate> certificates = new LinkedList<>();

    public DiceSubjectVerifier certificates(List<X509Certificate> certificates) {
        this.certificates = certificates;
        return this;
    }

    public boolean verify() {
        try {
            return !certificates.isEmpty() && verifyInternal();
        } catch (InvalidDiceCertificateSubjectException e) {
            log.error("One of certificates that contain UEID extension has invalid subject, that could not be parsed.",
                e);
        } catch (Exception e) {
            log.error("Failed to verify DICE certificate subjects in chain, unexpected error occurred.", e);
        }
        return false;
    }

    private boolean verifyInternal() {
        final var diceSubjects = certificates.stream()
            .filter(this::containsUeidExtension)
            .map(cert -> cert.getSubjectX500Principal().getName())
            .map(DiceCertificateSubject::parse)
            .collect(Collectors.toList());

        final Optional<DiceCertificateSubject> anyDiceSubject = diceSubjects.stream().findAny();
        if (anyDiceSubject.isEmpty()) {
            log.warn("None of certificates in chain contains UEID extension, skipping DICE subject verification.");
            return true;
        }

        return verifySubjectsInChainAreConsistent(diceSubjects)
            && verifySubjectComponentsValuesAreCorrect(anyDiceSubject.get());
    }

    private boolean containsUeidExtension(final X509Certificate certificate) {
        final var ueidOid = new ASN1ObjectIdentifier(TCG_DICE_UEID.getOid());
        return containsExtension(certificate, ueidOid);
    }

    private boolean verifySubjectsInChainAreConsistent(List<DiceCertificateSubject> diceSubjects) {
        final Stream<Function<DiceCertificateSubject, Object>> gettersForComponentsThatMustBeConsistent = Stream.of(
            DiceCertificateSubject::getFamilyName,
            DiceCertificateSubject::getCompanyName,
            DiceCertificateSubject::getDeviceId);

        return gettersForComponentsThatMustBeConsistent
            .allMatch(componentGetter -> verifySubjectComponentIsConsistent(diceSubjects, componentGetter));
    }

    private boolean verifySubjectComponentIsConsistent(List<DiceCertificateSubject> diceSubjects,
                                                       Function<DiceCertificateSubject, Object> getSubjectComponent) {
        final var distinctComponentValues = diceSubjects.stream()
            .map(getSubjectComponent)
            .distinct()
            .map(Object::toString)
            .collect(Collectors.toList());
        final boolean valid = distinctComponentValues.size() == 1;
        if (!valid) {
            log.error("Inconsistent subject component - all certificates in chain should have the same value."
                + "\nDistinct values in chain: {}", String.join(", ", distinctComponentValues));
        }
        return valid;
    }

    private boolean verifySubjectComponentsValuesAreCorrect(DiceCertificateSubject diceSubject) {
        return verifyFamilyNameValue(diceSubject.getFamilyName())
            && verifyCompanyValue(diceSubject.getCompanyName());
    }

    private boolean verifyFamilyNameValue(String familyName) {
        String capitalizedFamilyName;
        try {
            capitalizedFamilyName = StringUtils.capitalize(AttFamily.from(familyName).getFamilyName());
        } catch (UnknownFamilyIdException e) {
            log.error("Unknown family name in certificate subject in chain: " + familyName);
            return false;
        }

        final boolean valid = capitalizedFamilyName.equals(familyName);
        if (!valid) {
            log.error("Family name has incorrect letter size.\nExpected: {}\nActual: {}",
                capitalizedFamilyName, familyName);
        }
        return valid;
    }

    private boolean verifyCompanyValue(String company) {
        final boolean valid = DiceCertificateSubject.COMPANY_NAME.equals(company);
        if (!valid) {
            log.error("Company name in certificate subject is incorrect.\nExpected: {}\nActual: {}",
                DiceCertificateSubject.COMPANY_NAME, company);
        }
        return valid;
    }
}
