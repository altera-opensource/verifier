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

package com.intel.bkp.fpgacerts.dice.tcbinfo;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Getter
public class TcbInfoParser {

    static List<TcbInfo> parseMultiTcbInfo(ASN1Encodable extension) {
        return Arrays.stream(DLSequence.getInstance(extension).toArray())
            .map(TcbInfoParser::parseTcbInfo)
            .collect(Collectors.toList());
    }

    static TcbInfo parseTcbInfo(ASN1Encodable asn1Encodable) {
        final TcbInfo tcbInfo = new TcbInfo();
        Arrays.stream(DLSequence.getInstance(asn1Encodable).toArray())
            .map(DLTaggedObject::getInstance)
            .forEach(obj -> TcbInfoParser.parseObject(obj, tcbInfo));
        return tcbInfo;
    }

    private static void parseObject(ASN1TaggedObject asn1Encodable, TcbInfo tcbInfo) {
        tcbInfo.add(TcbInfoField.from(asn1Encodable.getTagNo()), asn1Encodable);
    }
}
