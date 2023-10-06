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

package com.intel.bkp.fpgacerts.cbor;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CborTagsConstant {

    public static final int CBOR_RIM_MAIN_TAG = 500;
    public static final int CBOR_RIM_UNSIGNED_TAG = 501;
    public static final int CBOR_RIM_SIGNED_TAG = 502;
    public static final int CBOR_XRIM_SIGNED_TAG = 527;
    public static final int CBOR_XRIM_MAIN_TAG = 525;
    public static final int CBOR_XRIM_UNSIGNED_TAG = 526;
    public static final int CBOR_COSE_SIGN_TAG = 18;

    public static final int CBOR_LOCATOR_ITEM_TAG = 32;

    public static final int CBOR_LOCATOR_ITEM_KEY = 0;

    // PROTECTED
    public static final int CBOR_PROT_META_MAP_SIGNER_KEY = 0;
    public static final int CBOR_PROT_META_MAP_SIGNATURE_VALIDITY = 1;
    public static final int CBOR_PROT_META_MAP_NOT_AFTER = 1;
    public static final int CBOR_PROT_META_MAP_DATE = 0;
}
