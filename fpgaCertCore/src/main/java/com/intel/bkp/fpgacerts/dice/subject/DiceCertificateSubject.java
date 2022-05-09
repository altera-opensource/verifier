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

package com.intel.bkp.fpgacerts.dice.subject;

import com.intel.bkp.fpgacerts.exceptions.InvalidDiceCertificateSubjectException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

@Getter
@RequiredArgsConstructor
public class DiceCertificateSubject {

    private static final Character DICE_SUBJECT_DELIMITER = ':';
    private static final int COMPONENTS_COUNT = 5;
    private static final String COMPANY_NAME = "Intel";

    private final String companyName;
    private final String familyName;
    private final String level;
    private final String additionalData; // SVN (for enrollment cert) or SKI (for deviceId cert or IID UDS cert)
    private final String deviceId;

    public static String build(String familyName, String levelCode, String additionalData, String deviceId) {
        return build(COMPANY_NAME, familyName, levelCode, additionalData, deviceId);
    }

    private static String build(String companyName, String familyName, String levelCode, String additionalData,
                                String deviceId) {
        final var components = List.of(companyName, familyName, levelCode, additionalData, deviceId);
        final var commonNameValue = String.join(DICE_SUBJECT_DELIMITER.toString(), components);
        return new Rdn(Rdn.COMMON_NAME_TYPE, commonNameValue).toString();
    }

    public static DiceCertificateSubject parse(String subject) {
        final String[] components = StringUtils.split(getCommonNameValue(subject), DICE_SUBJECT_DELIMITER);

        if (components.length != COMPONENTS_COUNT) {
            throw new InvalidDiceCertificateSubjectException(String.format(
                "Incorrect subject format - it doesn't consist of exactly %d parts delimited with %s.",
                COMPONENTS_COUNT, DICE_SUBJECT_DELIMITER));
        }

        String companyName = components[0];
        String familyName = components[1];
        String level = components[2];
        String additionalData = components[3];
        String deviceId = components[4];

        return new DiceCertificateSubject(companyName, familyName, level, additionalData, deviceId);
    }

    private static String getCommonNameValue(String subject) {
        return Rdn.parseDomainName(subject)
            .filter(rdn -> Rdn.COMMON_NAME_TYPE.equals(rdn.getType()))
            .map(Rdn::getValue)
            .findFirst()
            .orElseThrow(() ->
                new InvalidDiceCertificateSubjectException("Subject doesn't contain valid CommonName."));
    }

    @Override
    public String toString() {
        return DiceCertificateSubject.build(companyName, familyName, level, additionalData, deviceId);
    }

    @Getter
    @RequiredArgsConstructor
    private static class Rdn {

        /**
         * Attribute type for CommonName RDN.
         */
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
        public static final String COMMON_NAME_TYPE = "CN";
        /**
         * Delimiter of RDNs (Relative Distinguished Names) in DN (domain name).
         */
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
        private static final Character RDNS_SEPARATOR = ',';
        /**
         * Separator between type and value in RDN.
         */
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
        private static final Character TYPE_AND_VALUE_SEPARATOR = '=';

        private final String type;
        private final String value;

        @Override
        public String toString() {
            return String.format("%s%s%s", type, TYPE_AND_VALUE_SEPARATOR, value);
        }

        public static Stream<Rdn> parseDomainName(String domainName) {
            return Arrays.stream(StringUtils.split(domainName, RDNS_SEPARATOR))
                .map(Rdn::fromString);
        }

        private static Rdn fromString(String rdnString) {
            final var rdnParts = StringUtils.split(rdnString, TYPE_AND_VALUE_SEPARATOR);
            if (rdnParts.length != 2) {
                throw new InvalidDiceCertificateSubjectException(
                    String.format("Subject contains invalid RDN: '%s' that does not match format 'type%svalue'",
                        rdnString, TYPE_AND_VALUE_SEPARATOR)
                );
            }
            return new Rdn(rdnParts[0], rdnParts[1]);
        }
    }
}
