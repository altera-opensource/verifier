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

package com.intel.bkp.fpgacerts.cbor.utils;

import com.intel.bkp.fpgacerts.cbor.exception.RimVerificationException;
import com.intel.bkp.fpgacerts.utils.OidConverter;
import com.intel.bkp.fpgacerts.utils.VerificationStatusLogger;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.stream.Collectors;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public class ProfileValidator {

    public static final String EXPECTED_PROFILE = "6086480186F84D010F06"; // oid: 2.16.840.1.113741.1.15.6

    public static void verify(List<String> profiles) {
        if (isUnsupportedProfile(profiles)) {
            final String actualProfiles = describeActualProfiles(profiles);
            final String expectedProfile = describeExpectedProfile();
            throw new RimVerificationException("%nDetected unsupported profile: %s.%nSupported profile: %s"
                .formatted(actualProfiles, expectedProfile));
        }
        log.info(VerificationStatusLogger.success("CoRIM profile verification"));
    }

    private static String describeExpectedProfile() {
        return describe(EXPECTED_PROFILE);
    }

    private static String describeActualProfiles(List<String> profiles) {
        String actualProfiles = profiles.stream()
            .map(ProfileValidator::describe)
            .collect(Collectors.joining(", "));

        if (StringUtils.isBlank(actualProfiles)) {
            actualProfiles = "NONE";
        }
        return actualProfiles;
    }

    private static boolean isUnsupportedProfile(List<String> profiles) {
        return profiles.isEmpty() || !profiles.contains(EXPECTED_PROFILE);
    }

    private static String describe(String profile) {
        return "%s (%s)".formatted(OidConverter.fromHexOid(profile), profile);
    }
}
