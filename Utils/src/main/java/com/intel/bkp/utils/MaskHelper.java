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

package com.intel.bkp.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;

import static com.intel.bkp.utils.BitUtils.and;
import static com.intel.bkp.utils.HexConverter.fromHex;
import static com.intel.bkp.utils.HexConverter.toHex;
import static com.intel.bkp.utils.PaddingUtils.padRight;
import static com.intel.bkp.utils.StringHelper.truncateEnding;
import static com.intel.bkp.utils.StringHelper.zeroExtendEnding;
import static com.intel.bkp.utils.StringHelper.zeroExtendEndingToEvenLength;

@NoArgsConstructor(access = AccessLevel.NONE)
public class MaskHelper {

    /**
     * Creates mask with all F's of given length.
     * Example:
     * MaskHelper.getMask(4) = "FFFF"
     * MaskHelper.getMask(1) = "F"
     * MaskHelper.getMask(0) = ""
     * MaskHelper.getMask(-2) = ""
     */
    public static String getMask(int length) {
        return StringUtils.repeat("F", length);
    }

    /**
     * Applies mask on value, by first aligning value to match mask length (zero extend ending or truncate ending).
     *
     * @param value hexadecimal string with value for applying mask
     * @param mask hexadecimal string with mask which should be applied to value
     *
     * @return masked value of length exactly the same as mask length
     */
    @SneakyThrows(MismatchedMaskLengthException.class)
    public static String applyMask(String value, String mask) {
        final String valueAlignedToMask = alignToMask(value, mask.length());
        final byte[] valueBytes = fromHex(zeroExtendEndingToEvenLength(valueAlignedToMask));
        final byte[] maskBytes = fromHex(zeroExtendEndingToEvenLength(mask));

        final byte[] maskedValue = applyMask(valueBytes, maskBytes);
        return alignToMask(toHex(maskedValue), mask.length());
    }

    /**
     * Applies mask on value, if they have the same length, otherwise throws.
     *
     * @param value byte array with value for applying mask
     * @param mask byte array with mask which should be applied to value
     *
     * @return masked value with length the same as mask (trailing zero bytes included)
     */
    public static byte[] applyMask(byte[] value, byte[] mask) throws MismatchedMaskLengthException {
        if (value.length != mask.length) {
            throw new MismatchedMaskLengthException();
        }

        final byte[] maskedValue = and(value, mask);
        return padRight(maskedValue, mask.length);
    }

    private static String alignToMask(String value, int maskLength) {
        return value.length() <= maskLength
               ? zeroExtendEnding(value, maskLength)
               : truncateEnding(value, maskLength);
    }

    public static class MismatchedMaskLengthException extends Exception {
    }
}
