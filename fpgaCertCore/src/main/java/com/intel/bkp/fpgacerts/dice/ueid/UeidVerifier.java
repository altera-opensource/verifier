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

package com.intel.bkp.fpgacerts.dice.ueid;

import com.intel.bkp.fpgacerts.dice.subject.DiceCertificateSubject;
import com.intel.bkp.fpgacerts.model.AttFamily;
import com.intel.bkp.fpgacerts.utils.DeviceIdUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.X509CertificateUtils.containsExtension;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_UEID;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toFormattedHex;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
public class UeidVerifier {

    private final UeidExtensionParser extensionParser = new UeidExtensionParser();

    private List<X509Certificate> certificates = new LinkedList<>();

    public UeidVerifier certificates(List<X509Certificate> certificates) {
        this.certificates = certificates;
        return this;
    }

    public boolean verify(byte[] deviceId) {
        return certificates.stream().allMatch(c -> verifyCertificate(c, deviceId));
    }

    public boolean verifyCertificate(final X509Certificate certificate, final byte[] deviceId) {
        if (!containsUeidExtension(certificate)) {
            log.debug("Certificate does not contain UEID extension: {}", certificate.getSubjectX500Principal());
            return true;
        }

        final var ueidExtension = getUeidExtension(certificate);
        final var diceSubject = parseSubject(certificate);
        return ueidExtension.isPresent() && diceSubject.isPresent()
            && verifyDeviceIdMatches(ueidExtension.get(), diceSubject.get(), deviceId)
            && verifyFamilyMatches(ueidExtension.get(), diceSubject.get());
    }

    private boolean containsUeidExtension(final X509Certificate certificate) {
        final var ueidOid = new ASN1ObjectIdentifier(TCG_DICE_UEID.getOid());
        return containsExtension(certificate, ueidOid);
    }

    private Optional<UeidExtension> getUeidExtension(final X509Certificate certificate) {
        try {
            return Optional.of(extensionParser.parse(certificate));
        } catch (Exception ex) {
            log.error("Failed to parse UEID extension of certificate: {}", certificate.getSubjectX500Principal());
            return Optional.empty();
        }
    }

    private boolean verifyDeviceIdMatches(final UeidExtension ueidExtension, final DiceCertificateSubject diceSubject,
                                          final byte[] deviceId) {
        final byte[] uid = ueidExtension.getUid();
        return verifyMatchesExpectedDeviceId(uid, deviceId, diceSubject)
            && verifyMatchesSubject(uid, diceSubject);
    }

    private boolean verifyMatchesExpectedDeviceId(final byte[] uid, final byte[] deviceId,
                                                  final DiceCertificateSubject diceSubject) {
        final boolean match = Arrays.equals(deviceId, uid);
        if (!match) {
            log.error("Certificate has UEID extension with uid that does not match deviceId: {}"
                + "\nExpected: {}\nActual: {}", diceSubject, toHex(deviceId), toHex(uid));
        }
        return match;
    }

    private boolean verifyMatchesSubject(final byte[] uid, final DiceCertificateSubject diceSubject) {
        final byte[] uidBasedOnSubject = fromHex(DeviceIdUtil.getReversed(diceSubject.getDeviceId()));
        final boolean match = Arrays.equals(uidBasedOnSubject, uid);
        if (!match) {
            log.error("Certificate has UEID extension with uid that does not match uid based on subject: {}"
                    + "\nUid based on subject: {}\nUid in UEID extension: {}",
                diceSubject, toHex(uidBasedOnSubject), toHex(uid));
        }
        return match;
    }

    private boolean verifyFamilyMatches(final UeidExtension ueidExtension, final DiceCertificateSubject diceSubject) {
        final Optional<AttFamily> familyBasedOnSubject = getFamilyBasedOnSubject(diceSubject);
        if (familyBasedOnSubject.isEmpty()) {
            return false;
        }

        final byte familyIdBasedOnSubject = familyBasedOnSubject.get().getFamilyId();
        final byte familyIdFromExtension = ueidExtension.getFamilyId();
        final boolean match = familyIdBasedOnSubject == familyIdFromExtension;
        if (!match) {
            log.error("Certificate has UEID extension with familyId that does not match family based on subject: {}"
                    + "\nExpected: {} ({})\nActual: {} ({})", diceSubject,
                toFormattedHex(familyIdBasedOnSubject), familyBasedOnSubject.get().getFamilyName(),
                toFormattedHex(familyIdFromExtension), ueidExtension.getFamilyName());
        }
        return match;
    }

    private Optional<AttFamily> getFamilyBasedOnSubject(final DiceCertificateSubject subject) {
        try {
            return Optional.of(AttFamily.from(subject.getFamilyName()));
        } catch (Exception ex) {
            log.error("Failed to recognize family name from subject of certificate: {}\nDetails: {}",
                subject, ex.getMessage());
            return Optional.empty();
        }
    }

    private Optional<DiceCertificateSubject> parseSubject(final X509Certificate certificate) {
        final String subject = certificate.getSubjectX500Principal().getName();
        try {
            return Optional.of(DiceCertificateSubject.parse(subject));
        } catch (Exception ex) {
            log.error("Failed to parse subject of certificate: {}\nDetails: {}", subject, ex.getMessage());
            return Optional.empty();
        }
    }
}
