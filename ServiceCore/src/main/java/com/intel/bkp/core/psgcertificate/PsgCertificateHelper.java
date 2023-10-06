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

import com.intel.bkp.core.endianness.EndiannessActor;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.core.exceptions.PublicKeyHelperException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateChainWrongSizeException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidLeafCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidParentCertificatesException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidRootCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.psgcertificate.model.PsgRootCertMagic;
import com.intel.bkp.crypto.CertificateEncoder;
import com.intel.bkp.crypto.curve.CurvePoint;
import com.intel.bkp.crypto.curve.EcSignatureAlgorithm;
import com.intel.bkp.crypto.exceptions.InvalidSignatureException;
import com.intel.bkp.crypto.impl.EcUtils;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.Predicate;

import static com.intel.bkp.core.psgcertificate.PsgCertificateEntryBuilder.PUBLIC_KEY_ENTRY_MAGIC;

public class PsgCertificateHelper {

    private static final int MIN_CHAIN_LENGTH = 2;
    private static final int MAX_CHAIN_LENGTH = 3;
    private static final String FAILED_TO_CHECK_SIGNATURE = "Failed to check signature";

    static void verifyEntryMagic(int magic) throws PsgCertificateException {
        if (PUBLIC_KEY_ENTRY_MAGIC != magic) {
            throw new PsgCertificateException("Invalid public key entry magic.");
        }
    }

    static void verifyRootEntryMagic(int magic) throws PsgCertificateException {
        if (!PsgRootCertMagic.isValid(magic)) {
            throw new PsgCertificateException("Invalid root key entry magic.");
        }
    }

    public List<CertificateEntryWrapper> getCertificateChainList(String encodedChain) {
        byte[] decodedChain = CertificateEncoder.sanitizeChainPayloadBase64(encodedChain);

        ByteBufferSafe decryptedDataBuffer = ByteBufferSafe.wrap(decodedChain);

        List<CertificateEntryWrapper> dataList = new ArrayList<>();
        while (decryptedDataBuffer.remaining() >= 2 * Integer.BYTES) {
            decryptedDataBuffer.mark();
            int magic = decryptedDataBuffer.getInt();
            int length = decryptedDataBuffer.getInt();

            if (PUBLIC_KEY_ENTRY_MAGIC == magic) {
                decryptedDataBuffer.reset();
                dataList.add(getCertificate(decryptedDataBuffer, length, PsgCertificateType.LEAF));
            } else if (PsgRootCertMagic.isValid(magic)) {
                decryptedDataBuffer.reset();
                dataList.add(getCertificate(decryptedDataBuffer, length, PsgCertificateType.ROOT));
            }
        }
        return dataList;
    }

    private CertificateEntryWrapper getCertificate(ByteBufferSafe bufferSafe, int length, PsgCertificateType type) {
        byte[] certificateContent = bufferSafe.arrayFromInt(length);
        bufferSafe.get(certificateContent);
        return new CertificateEntryWrapper(type, certificateContent);
    }

    public void verifyChainListSizeInternal(List<CertificateEntryWrapper> certificateChainList)
        throws PsgCertificateChainWrongSizeException {
        Predicate<CertificateEntryWrapper> predicate = s -> s.getType() == PsgCertificateType.ROOT;
        if (certificateChainList.size() < MIN_CHAIN_LENGTH
            || certificateChainList.size() > MAX_CHAIN_LENGTH
            || certificateChainList.stream().filter(predicate).count() != 1) {
            throw new PsgCertificateChainWrongSizeException();
        }
    }

    public static String generateFingerprint(PsgCertificateRootEntryBuilder psgCertificateBuilder) {
        return PsgPublicKeyHelper.from(psgCertificateBuilder.getPsgPublicKeyBuilder()).generateFingerprint();
    }

    public static String generateSha256Fingerprint(PsgCertificateRootEntryBuilder psgCertificateBuilder) {
        return PsgPublicKeyHelper.from(psgCertificateBuilder.getPsgPublicKeyBuilder()).generateSha256Fingerprint();
    }

    private boolean verifyRootCertificateInternal(
        PsgCertificateRootEntryBuilder root, PsgCertificateRootEntryBuilder certObj) {
        return generateFingerprint(root).equals(generateFingerprint(certObj));
    }

    public void verifyRootCertificateInternal(
        List<CertificateEntryWrapper> certificateChainList, byte[] rootCertificate)
        throws PsgCertificateChainWrongSizeException, PsgInvalidRootCertificateException {

        PsgCertificateRootEntryBuilder toVerifyEntry = findRootCertificateInChain(certificateChainList);
        PsgCertificateRootEntryBuilder rootEntry = parseRootCertificate(rootCertificate);

        if (!verifyRootCertificateInternal(rootEntry, toVerifyEntry)) {
            throw new PsgInvalidRootCertificateException();
        }
    }

    public PsgCertificateRootEntryBuilder findRootCertificateInChain(List<CertificateEntryWrapper> certificateChainList)
        throws PsgCertificateChainWrongSizeException, PsgInvalidRootCertificateException {
        final CertificateEntryWrapper rootCertificate = certificateChainList
            .stream()
            .filter(s -> s.getType() == PsgCertificateType.ROOT)
            .findFirst()
            .orElseThrow(PsgCertificateChainWrongSizeException::new);
        return parseRootCertificate(rootCertificate.getContent());
    }


    public PsgCertificateEntryBuilder findLeafCertificateInChain(List<CertificateEntryWrapper> certificateChainList)
        throws PsgCertificateChainWrongSizeException, PsgInvalidLeafCertificateException {
        final CertificateEntryWrapper leafCertificate = certificateChainList
            .stream()
            .filter(s -> s.getType() == PsgCertificateType.LEAF)
            .reduce((first, second) -> second)
            .orElseThrow(PsgCertificateChainWrongSizeException::new);
        return parseLeafCertificate(leafCertificate.getContent());
    }

    protected PsgCertificateRootEntryBuilder parseRootCertificate(byte[] rootCertificate)
        throws PsgInvalidRootCertificateException {
        try {
            return new PsgCertificateRootEntryBuilder().parse(rootCertificate);
        } catch (ByteBufferSafeException | ParseStructureException e) {
            throw new PsgInvalidRootCertificateException();
        }
    }

    private PsgCertificateEntryBuilder parseLeafCertificate(byte[] certificateContent)
        throws PsgInvalidLeafCertificateException {
        try {
            return new PsgCertificateEntryBuilder().parse(certificateContent);
        } catch (ByteBufferSafeException | ParseStructureException e) {
            throw new PsgInvalidLeafCertificateException();
        }
    }

    public boolean verifyParentsByPubKeyRecursive(CertificateEntryWrapper parentEntry,
                                                  Iterator<CertificateEntryWrapper> certificateChainIterator)
        throws PsgInvalidSignatureException {
        if (certificateChainIterator.hasNext()) {
            PsgCertificateCommon parsedParentEntry = parseWrappedEntry(parentEntry);
            CertificateEntryWrapper childEntry = certificateChainIterator.next();
            PsgCertificateCommon parsedChildEntry = parseWrappedEntry(childEntry);
            if (sigVerify(parsedParentEntry, parsedChildEntry)) {
                return verifyParentsByPubKeyRecursive(childEntry, certificateChainIterator);
            }
            return false;
        }
        return true;
    }

    private PsgCertificateCommon parseWrappedEntry(CertificateEntryWrapper entry) {
        if (entry.getType() == PsgCertificateType.ROOT) {
            return new PsgCertificateRootEntryBuilder().parse(entry.getContent()).build();
        } else {
            return new PsgCertificateEntryBuilder().parse(entry.getContent()).build();
        }
    }

    private boolean isSignatureInCertificate(IPsgCertificateWithSignature child) {
        return child.getPsgSignature().length > 0;
    }

    private byte[] getPsgPublicKeyForSignatureVerification(IPsgCertificateWithPubKey child) {
        return new PsgPublicKeyBuilder()
            .parse(child.getPsgPublicKey())
            .withActor(EndiannessActor.FIRMWARE)
            .build()
            .array();
    }

    public boolean sigVerify(PsgCertificateCommon parent, PsgCertificateCommon child)
        throws PsgInvalidSignatureException {
        try {
            if (!(parent instanceof IPsgCertificateWithPubKey)
                || !(child instanceof IPsgCertificateWithPubKey)
                || !(child instanceof IPsgCertificateWithSignature)
                || !isSignatureInCertificate((IPsgCertificateWithSignature) child)) {
                return false;
            }

            final CurvePoint curvePoint = getCurvePoint((IPsgCertificateWithSignature) child);
            final EcSignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm((IPsgCertificateWithPubKey) child);
            final ECPublicKey publicKey = decodeKey((IPsgCertificateWithPubKey) parent);
            final byte[] data = getPsgPublicKeyForSignatureVerification((IPsgCertificateWithPubKey) child);
            return sigVerify(signatureAlgorithm, publicKey, data, curvePoint);
        } catch (PublicKeyHelperException e) {
            throw new PsgInvalidSignatureException(FAILED_TO_CHECK_SIGNATURE, e);
        }
    }

    public static boolean sigVerify(EcSignatureAlgorithm signatureAlgorithm, PublicKey publicKey, byte[] data,
                                    CurvePoint signaturePoint) throws PsgInvalidSignatureException {
        try {
            return EcUtils.sigVerify(publicKey, data, signaturePoint, signatureAlgorithm.getBcAlgName());
        } catch (InvalidSignatureException e) {
            throw new PsgInvalidSignatureException(FAILED_TO_CHECK_SIGNATURE, e);
        }
    }

    private CurvePoint getCurvePoint(IPsgCertificateWithSignature child) {
        return new PsgSignatureBuilder().parse(child.getPsgSignature()).getCurvePoint();
    }

    private EcSignatureAlgorithm getSignatureAlgorithm(IPsgCertificateWithPubKey entry) {
        final CurvePoint pubKeyPoint = new PsgPublicKeyBuilder().parse(entry.getPsgPublicKey()).getCurvePoint();
        return EcSignatureAlgorithm.fromCurveSpec(pubKeyPoint.getCurveSpec());
    }

    private ECPublicKey decodeKey(IPsgCertificateWithPubKey parent)
        throws PublicKeyHelperException {
        return (ECPublicKey) PsgPublicKeyHelper.from(parent.getPsgPublicKey()).toPublic();
    }

    public void verifyParentsInChainByPubKey(List<CertificateEntryWrapper> certificateChainList)
        throws PsgInvalidParentCertificatesException, PsgInvalidSignatureException {

        Iterator<CertificateEntryWrapper> iterator = certificateChainList.iterator();
        if (iterator.hasNext() && !verifyParentsByPubKeyRecursive(iterator.next(), iterator)) {
            throw new PsgInvalidParentCertificatesException();
        }
    }
}
