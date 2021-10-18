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

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.io.IOException;
import java.util.Locale;

@Slf4j
@Getter
public abstract class BaseExtensionParser {

    protected String getExtensionParsingError() {
        return "Failed to parse extension.";
    }

    protected final ASN1Encodable parseExtension(byte[] bytes) {
        try {
            return JcaX509ExtensionUtils.parseExtensionValue(bytes);
        } catch (IOException e) {
            throw new IllegalArgumentException(getExtensionParsingError());
        }
    }

    protected final ASN1Sequence parseSequence(ASN1Encodable asn1Encodable) {
        return parseSequence(asn1Encodable, 1);
    }

    protected final ASN1Sequence parseSequence(ASN1Encodable asn1Encodable, int expectedElemCount) {
        final ASN1Sequence sequence = DLSequence.getInstance(asn1Encodable);

        if (sequence.size() != expectedElemCount) {
            throw new IllegalArgumentException(String.format(
                "Extension has incorrect number of fields in sequence: %s", sequence));
        }

        return sequence;
    }

    protected final String parseAsn1Identifier(ASN1Encodable object) {
        return ASN1ObjectIdentifier.getInstance(object).getId().toUpperCase(Locale.ROOT);
    }

    protected final byte[] parseOctetString(ASN1Encodable asn1Encodable) {
        return DEROctetString.getInstance(asn1Encodable).getOctets();
    }

    protected final byte[] parseOctetString(ASN1TaggedObject asn1TaggedObject) {
        return parseOctetString(asn1TaggedObject.getObject());
    }
}
