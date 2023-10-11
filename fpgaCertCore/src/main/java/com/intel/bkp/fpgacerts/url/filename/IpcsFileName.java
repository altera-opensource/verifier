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

package com.intel.bkp.fpgacerts.url.filename;

import lombok.Getter;

public enum IpcsFileName {
    S10("attestation_%s_%s.cer"), // attestation_<deviceid>_<puftype_hex>.cer
    DEVICE_ID("deviceid_%s_%s.cer"), // deviceid_<uid>_<ski or pdi>.cer
    IID_UDS("iiduds_%s_%s.cer"), // iiduds_<uid>_<ski>.cer
    ENROLLMENT("enrollment_%s_%s_%s.cer"), // enrollment_<uid>_<svn>_<skiER>.cer
    PUFHELPDATA("iiduds_%s_%s.puf"), // iiduds_<uid>_<ski>.puf
    INTEL_PUFHELPDATA("deviceid_%s_%s.puf"), // deviceid_<uid>_<pdi>.puf
    NIC_MEV_DEVICE_ID("%s_%s.cer"), // <familyId>_<uid>.cer
    NIC_DEVICE_ID("%s_%s_%s.cer"), // <familyId>_<uid>_<ski>.cer
    RIM_SIGNING("RIM_Signing_%s_%s.cer"), // RIM_Signing_<familyName>_<ski>.cer
    XRIM_SIGNED_DATA("RIM_Signing_%s_%s.xcorim"), // RIM_Signing_<familyName>_<ski>.xcorim
    RIM_SIGNED_DATA("%s_%s_%s.corim"), // <family>_<layer>_<fwid>.corim
    ZIP_DICE("%s_%s_%s.zip"); // <family>_<uid>_<ski or pdi>.zip

    @Getter
    private final String fileNameTemplate;
    @Getter
    private final String fileNamePrefix;

    IpcsFileName(String fileNameTemplate) {
        this.fileNameTemplate = fileNameTemplate;
        this.fileNamePrefix = fileNameTemplate.substring(0, fileNameTemplate.indexOf('_') + 1);
    }
}
