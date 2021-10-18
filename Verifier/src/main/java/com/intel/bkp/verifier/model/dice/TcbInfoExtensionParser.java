/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.model.dice;

import com.intel.bkp.verifier.interfaces.ICertificateParser;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_MULTI_TCB_INFO;
import static com.intel.bkp.verifier.model.AttestationOid.TCG_DICE_TCB_INFO;

@Slf4j
@Getter
public class TcbInfoExtensionParser extends BaseExtensionParser implements ICertificateParser {

    private final List<TcbInfo> tcbInfos = new ArrayList<>();

    @Override
    public void parse(X509Certificate certificate) {
        final Optional<X509Certificate> certOptional = Optional.ofNullable(certificate);
        certOptional.ifPresent(
            cert -> log.debug("Parsing TcbInfo from certificate: {}", cert.getSubjectDN()));
        parseSingleTcbInfoExtension(certOptional);
        parseMultiTbInfoExtension(certOptional);
    }

    private void parseMultiTbInfoExtension(Optional<X509Certificate> certOptional) {
        certOptional
            .map(c -> c.getExtensionValue(TCG_DICE_MULTI_TCB_INFO.getOid()))
            .map(this::parseExtension)
            .ifPresent(this::parseMultiTcbInfo);
    }

    private void parseSingleTcbInfoExtension(Optional<X509Certificate> certOptional) {
        certOptional
            .map(c -> c.getExtensionValue(TCG_DICE_TCB_INFO.getOid()))
            .map(this::parseExtension)
            .ifPresent(this::parseTcbInfo);
    }

    private void parseMultiTcbInfo(ASN1Encodable extension) {
        final ASN1Sequence sequence = DLSequence.getInstance(extension);
        sequence.forEach(this::parseTcbInfo);
    }

    private void parseTcbInfo(ASN1Encodable asn1Encodable) {
        final TcbInfo tcbInfo = new TcbInfo();
        Arrays.stream(DLSequence.getInstance(asn1Encodable).toArray())
            .map(DLTaggedObject::getInstance)
            .forEach(obj -> parseObject(obj, tcbInfo));
        tcbInfos.add(tcbInfo);
    }

    private void parseObject(ASN1TaggedObject asn1Encodable, TcbInfo tcbInfo) {
        tcbInfo.add(TcbInfoField.from(asn1Encodable.getTagNo()), asn1Encodable);
    }
}
