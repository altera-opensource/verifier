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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.endianness.StructureType;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.psgcertificate.model.PsgSignature;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgSignatureMagic;
import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.crypto.interfaces.ICurveSpec;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.Getter;
import lombok.Setter;

import static com.intel.bkp.core.endianness.StructureField.PSG_SIG_HASH_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_SIG_MAGIC;
import static com.intel.bkp.core.endianness.StructureField.PSG_SIG_SIZE_R;
import static com.intel.bkp.core.endianness.StructureField.PSG_SIG_SIZE_S;

@Setter
@Getter
public class PsgSignatureBuilder extends StructureBuilder<PsgSignatureBuilder, PsgSignature> {

    private static final int SIGNATURE_METADATA_SIZE = 4 * Integer.BYTES;

    private PsgSignatureMagic magic = PsgSignatureMagic.STANDARD;

    private int sizeR = 0;
    private int sizeS = 0;

    private CurvePoint curvePoint;

    public PsgSignatureBuilder() {
        super(StructureType.PSG_SIGNATURE);
    }

    @Override
    public PsgSignatureBuilder self() {
        return this;
    }

    public static PsgSignatureBuilder empty(PsgSignatureCurveType curveType) {
        return new PsgSignatureBuilder()
            .curvePoint(CurvePoint.from(new byte[]{0}, new byte[]{0}, curveType.getCurveSpec()));
    }

    public PsgSignatureBuilder signature(byte[] signedData, PsgSignatureCurveType signatureType) {
        this.curvePoint = CurvePoint.fromSignature(signedData, signatureType);
        return this;
    }

    public int getTotalSignatureSize() {
        return getTotalSignatureSize(getCurvePoint());
    }

    public static int getTotalSignatureSize(ICurveSpec curveSpec) {
        return (2 * curveSpec.getCurveSpec().getSize()) + SIGNATURE_METADATA_SIZE;
    }

    public PsgSignature build() {
        PsgSignature psgSignature = new PsgSignature();
        psgSignature.setSignatureMagic(convert(magic.getValue(), PSG_SIG_MAGIC));
        psgSignature.setSizeR(convert(sizeR, PSG_SIG_SIZE_R));
        psgSignature.setSizeS(convert(sizeS, PSG_SIG_SIZE_S));
        psgSignature.setSignatureHashMagic(convert(PsgSignatureCurveType.fromCurveSpec(curvePoint.getCurveSpec())
                .getMagic(),
            PSG_SIG_HASH_MAGIC));
        psgSignature.setSignatureR(curvePoint.getPointA());
        psgSignature.setSignatureS(curvePoint.getPointB());
        return psgSignature;
    }

    public PsgSignatureBuilder parse(ByteBufferSafe buffer) throws ParseStructureException {
        magic = PsgSignatureMagic.from(convertInt(buffer.getInt(), PSG_SIG_MAGIC));

        sizeR = convertInt(buffer.getInt(), PSG_SIG_SIZE_R);
        sizeS = convertInt(buffer.getInt(), PSG_SIG_SIZE_S);

        final PsgSignatureCurveType signatureType = PsgSignatureCurveType.fromMagic(convertInt(buffer.getInt(),
            PSG_SIG_HASH_MAGIC));

        this.curvePoint = CurvePoint.from(buffer, signatureType.getCurveSpec());
        return this;
    }

    private PsgSignatureBuilder curvePoint(CurvePoint curvePoint) {
        this.curvePoint = curvePoint;
        return this;
    }
}
