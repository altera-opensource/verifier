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

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.psgcertificate.PsgCancellableBlock0EntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder;
import com.intel.bkp.core.psgcertificate.PsgCertificateRootEntryBuilder;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.RomExtensionSignatureException;
import com.intel.bkp.core.psgcertificate.exceptions.RomExtensionStrategyException;

enum RomExtractedStructureStrategy {
    ROOT {
        @Override
        public void parse(RomExtensionSignatureBuilder sigBuilder, EndianessActor actor, byte[] data)
            throws RomExtensionSignatureException {
            try {
                sigBuilder.setPsgCertRootBuilder(new PsgCertificateRootEntryBuilder()
                    .withActor(actor)
                    .parse(data));
            } catch (PsgCertificateException e) {
                throw new RomExtensionStrategyException(this.name(), e);
            }
        }
    },
    LEAF {
        @Override
        public void parse(RomExtensionSignatureBuilder sigBuilder, EndianessActor actor, byte[] data)
            throws RomExtensionSignatureException {
            try {
                sigBuilder.getPsgCertEntryBuilders()
                    .add(new PsgCertificateEntryBuilder()
                        .withActor(actor)
                        .parse(data));
            } catch (PsgCertificateException e) {
                throw new RomExtensionStrategyException(this.name(), e);
            }
        }
    },
    BLOCK0 {
        @Override
        public void parse(RomExtensionSignatureBuilder sigBuilder, EndianessActor actor, byte[] data)
            throws RomExtensionSignatureException {
            try {
                sigBuilder.setPsgCancellableBlock0EntryBuilder(new PsgCancellableBlock0EntryBuilder()
                    .withActor(actor)
                    .parse(data));
            } catch (Exception e) {
                throw new RomExtensionStrategyException(this.name(), e);
            }
        }
    };

    public abstract void parse(RomExtensionSignatureBuilder sigBuilder, EndianessActor actor, byte[] data)
        throws RomExtensionSignatureException;
}
