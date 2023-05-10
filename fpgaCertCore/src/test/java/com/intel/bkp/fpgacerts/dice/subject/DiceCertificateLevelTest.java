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

package com.intel.bkp.fpgacerts.dice.subject;

import com.intel.bkp.fpgacerts.exceptions.UnknownDiceCertificateLevelException;
import org.junit.jupiter.api.Test;

import static com.intel.bkp.fpgacerts.dice.subject.DiceCertificateLevel.ALIAS;
import static com.intel.bkp.fpgacerts.dice.subject.DiceCertificateLevel.DEVICE_ID;
import static com.intel.bkp.fpgacerts.dice.subject.DiceCertificateLevel.ENROLLMENT;
import static com.intel.bkp.fpgacerts.dice.subject.DiceCertificateLevel.FIRMWARE;
import static com.intel.bkp.fpgacerts.dice.subject.DiceCertificateLevel.IID_UDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DiceCertificateLevelTest {

    @Test
    void findByCode_ER_Success() {
        // when
        final DiceCertificateLevel result = DiceCertificateLevel.findByCode("ER");

        // then
        assertEquals(ENROLLMENT, result);
    }

    @Test
    void findByCode_PU_Success() {
        // when
        final DiceCertificateLevel result = DiceCertificateLevel.findByCode("PU");

        // then
        assertEquals(IID_UDS, result);
    }

    @Test
    void findByCode_L0_Success() {
        // when
        final DiceCertificateLevel result = DiceCertificateLevel.findByCode("L0");

        // then
        assertEquals(DEVICE_ID, result);
    }

    @Test
    void findByCode_L1_Success() {
        // when
        final DiceCertificateLevel result = DiceCertificateLevel.findByCode("L1");

        // then
        assertEquals(FIRMWARE, result);
    }

    @Test
    void findByCode_L2_Success() {
        // when
        final DiceCertificateLevel result = DiceCertificateLevel.findByCode("L2");

        // then
        assertEquals(ALIAS, result);
    }

    @Test
    void findByCode_NotExistingCode_Throws() {
        // when-then
        assertThrows(UnknownDiceCertificateLevelException.class, () -> DiceCertificateLevel.findByCode("AA"));
    }
}
