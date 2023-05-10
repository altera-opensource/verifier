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

package com.intel.bkp.crypto.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CryptoConstants {

    public static final String CERTIFICATE_FACTORY_TYPE = "X.509";
    public static final String KEY_AGREEMENT_ALG_TYPE = "ECDH";
    public static final String ECDH_KEY = "ECDH";
    public static final String EC_KEY = "EC";
    public static final String AES_KEY = "AES";
    public static final String RSA_KEY = "RSA";
    public static final String SHA256_WITH_ECDSA = "SHA256withECDSA";
    public static final String SHA384_WITH_ECDSA = "SHA384withECDSA";
    public static final String SHA512_WITH_ECDSA = "SHA512withECDSA";
    public static final String SHA384_WITH_RSA = "SHA384withRSA";

    public static final String EC_CURVE_SPEC_521 = "secp521r1"; // NISTP521
    public static final String EC_CURVE_SPEC_384 = "secp384r1"; // NISTP384
    public static final String EC_CURVE_SPEC_256 = "secp256r1"; // NISTP256
    public static final String AES_CIPHER_TYPE = "GCM";
    public static final String RSA_CIPHER_TYPE = "RSA/None/OAEPWithSHA384AndMGF1Padding";

    public static final int AES_KEY_SIZE = 256;
    public static final int RSA_KEY_SIZE = 3072;

    public static final int SHA384_LEN = 48;
    public static final int SHA256_LEN = 32;
    public static final int SHA384_SIG_LEN = 2 * SHA384_LEN;

}
