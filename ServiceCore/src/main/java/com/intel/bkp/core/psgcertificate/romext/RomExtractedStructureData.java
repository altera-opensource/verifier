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

package com.intel.bkp.core.psgcertificate.romext;

import com.intel.bkp.core.psgcertificate.PsgCancellableBlock0EntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.exceptions.RomExtensionSignatureException;
import com.intel.bkp.core.psgcertificate.model.PsgRootCertMagic;
import lombok.Getter;

import static com.intel.bkp.utils.ByteConverter.toBytes;
import static com.intel.bkp.utils.HexConverter.toHex;

@Getter
class RomExtractedStructureData {

    private final RomExtractedStructureStrategy type;
    private final byte[] data;

    protected RomExtractedStructureData(int magic, byte[] data) throws RomExtensionSignatureException {
        this.type = getType(magic);
        this.data = data;
    }

    private RomExtractedStructureStrategy getType(int magic) throws RomExtensionSignatureException {
        if (PsgCancellableBlock0EntryBuilder.MAGIC == magic) {
            return RomExtractedStructureStrategy.BLOCK0;
        } else if (PsgRootCertMagic.isValid(magic)) {
            return RomExtractedStructureStrategy.ROOT;
        } else if (PsgCertificateEntryBuilder.PUBLIC_KEY_ENTRY_MAGIC == magic) {
            return RomExtractedStructureStrategy.LEAF;
        }
        throw new RomExtensionSignatureException("Invalid magic detected: " + toHex(toBytes(magic)));
    }
}
