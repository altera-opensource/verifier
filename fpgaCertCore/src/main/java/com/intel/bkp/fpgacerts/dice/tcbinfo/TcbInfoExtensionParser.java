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

import com.intel.bkp.fpgacerts.utils.BaseExtensionParser;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.X509ExtensionUtils.containsExtension;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_MULTI_TCB_INFO;
import static com.intel.bkp.fpgacerts.model.Oid.TCG_DICE_TCB_INFO;

@Slf4j
@Getter
public class TcbInfoExtensionParser extends BaseExtensionParser<List<TcbInfo>> {

    private static final String EXTENSION_NAME = "TcbInfo";

    public TcbInfoExtensionParser() {
        super(EXTENSION_NAME);
    }

    public static boolean containsTcbInfoExtension(final X509Extension x509Obj) {
        final var tcbInfoOid = TCG_DICE_TCB_INFO.getOid();
        final var multiTcbInfoOid = TCG_DICE_MULTI_TCB_INFO.getOid();
        return containsExtension(x509Obj, tcbInfoOid) || containsExtension(x509Obj, multiTcbInfoOid);
    }

    public List<TcbInfo> parse(@NonNull final X509Certificate certificate) {
        return parse((X509Extension) certificate);
    }

    public List<TcbInfo> parse(@NonNull final X509CRLEntry crlEntry) {
        return parse((X509Extension) crlEntry);
    }

    @Override
    protected List<TcbInfo> parse(@NonNull final X509Extension x509Obj) {
        logExtensionParsingStart(x509Obj, EXTENSION_NAME);

        final var tcbInfos = new ArrayList<TcbInfo>();
        parseSingleTcbInfoExtension(x509Obj).ifPresent(tcbInfos::add);
        parseMultiTbInfoExtension(x509Obj).ifPresent(tcbInfos::addAll);
        return tcbInfos;
    }

    private Optional<List<TcbInfo>> parseMultiTbInfoExtension(final X509Extension x509Obj) {
        return getExtension(x509Obj, TCG_DICE_MULTI_TCB_INFO.getOid())
            .map(TcbInfoParser::parseMultiTcbInfo);
    }

    private Optional<TcbInfo> parseSingleTcbInfoExtension(final X509Extension x509Obj) {
        return getExtension(x509Obj, TCG_DICE_TCB_INFO.getOid())
            .map(TcbInfoParser::parseTcbInfo);
    }
}
