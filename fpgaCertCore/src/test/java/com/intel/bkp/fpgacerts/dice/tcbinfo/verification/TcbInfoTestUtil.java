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

package com.intel.bkp.fpgacerts.dice.tcbinfo.verification;

import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfo;
import com.intel.bkp.fpgacerts.dice.tcbinfo.TcbInfoField;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;

import java.util.Arrays;

import static com.intel.bkp.utils.HexConverter.fromHex;

public class TcbInfoTestUtil {

    public static TcbInfo parseTcbInfo(String tcbInfoSequenceInHex) {
        return parseTcbInfo(fromHex(tcbInfoSequenceInHex));
    }

    /* Below method is based on TcbInfoExtensionParser - it enables using in tests TcbInfo ASN1 DER encoded sequences:
        - extracted from real certificates or samples,
        - generated using https://asn1.io/asn1playground/.

       To generate using https://asn1.io/asn1playground/ first compile schema, and then encode any value you want.
       Schema to compile:
            My-module DEFINITIONS ::=
            BEGIN
                DiceTcbInfo ::= SEQUENCE {
                    vendor    [0] IMPLICIT UTF8String	OPTIONAL,
                    model     [1] IMPLICIT UTF8String	OPTIONAL,
                    version   [2] IMPLICIT UTF8String	OPTIONAL,
                    svn       [3] IMPLICIT INTEGER      OPTIONAL,
                    layer     [4] IMPLICIT INTEGER      OPTIONAL,
                    index     [5] IMPLICIT INTEGER      OPTIONAL,
                    fwids     [6] IMPLICIT FWIDLIST     OPTIONAL,
                    flags     [7] IMPLICIT OperationalModes OPTIONAL,
                    vendorInfo[8] IMPLICIT OCTET STRING OPTIONAL,
                    type      [9] IMPLICIT OCTET STRING OPTIONAL
                }

                FWIDLIST ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
                    hashAlg OBJECT IDENTIFIER,
                    digest  OCTET STRING
                }

                OperationalModes ::= BIT STRING {
                    notConfigured (0),
                    notSecure (1),
                    recovery (2),
                    debug (3)
                }
            END

       Example value to encode:
            value DiceTcbInfo  ::= {
                vendor "intel.com",
                model "Agilex",
                svn 26,
                layer 0,
                index 0,
                fwids {
                    {
                        hashAlg 2.16.840.1.101.3.4.2.2,
                        digest
                        'ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'H
                    }
                },
                flags '01'B
            }

       You can also decode value to receive the above structure back again.
    */
    public static TcbInfo parseTcbInfo(byte[] tcbInfoSequence) {
        final TcbInfo tcbInfo = new TcbInfo();
        Arrays.stream(DLSequence.getInstance(tcbInfoSequence).toArray())
            .map(DLTaggedObject::getInstance)
            .forEach(obj -> parseObject(obj, tcbInfo));
        return tcbInfo;
    }

    private static void parseObject(ASN1TaggedObject asn1Encodable, TcbInfo tcbInfo) {
        tcbInfo.add(TcbInfoField.from(asn1Encodable.getTagNo()), asn1Encodable);
    }
}
