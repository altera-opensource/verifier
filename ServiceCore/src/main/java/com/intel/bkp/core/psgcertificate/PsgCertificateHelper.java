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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateChainWrongSizeException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidLeafCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidParentCertificatesException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidRootCertificateException;
import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.psgcertificate.model.PsgCurveType;
import com.intel.bkp.core.psgcertificate.model.PsgPublicKey;
import com.intel.bkp.core.psgcertificate.model.PsgRootCertMagic;
import com.intel.bkp.core.psgcertificate.model.PsgSignature;
import com.intel.bkp.crypto.CertificateEncoder;
import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.utils.ByteBufferSafe;
import com.intel.bkp.utils.exceptions.ByteBufferSafeException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
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
        return PsgPublicKeyHelper.generateFingerprint(psgCertificateBuilder.getPsgPublicKeyBuilder());
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
        } catch (ByteBufferSafeException | PsgCertificateException e) {
            throw new PsgInvalidRootCertificateException();
        }
    }

    private PsgCertificateEntryBuilder parseLeafCertificate(byte[] certificateContent)
        throws PsgInvalidLeafCertificateException {
        try {
            return new PsgCertificateEntryBuilder().parse(certificateContent);
        } catch (ByteBufferSafeException | PsgCertificateException e) {
            throw new PsgInvalidLeafCertificateException();
        }
    }

    public boolean verifyParentsByPubKeyRecursive(CertificateEntryWrapper parentEntry,
                                                  Iterator<CertificateEntryWrapper> certificateChainIterator)
        throws PsgCertificateException, PsgInvalidSignatureException {
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

    private PsgCertificateCommon parseWrappedEntry(CertificateEntryWrapper entry) throws PsgCertificateException {
        if (entry.getType() == PsgCertificateType.ROOT) {
            return new PsgCertificateRootEntryBuilder().parse(entry.getContent()).build();
        } else {
            return new PsgCertificateEntryBuilder().parse(entry.getContent()).build();
        }
    }

    private PsgSignature parsePsgSignature(IPsgCertificateWithSignature child) throws PsgInvalidSignatureException {
        return new PsgSignatureBuilder().parse(child.getPsgSignature()).build();
    }

    private boolean isSignatureInCertificate(IPsgCertificateWithSignature child) {
        return child.getPsgSignature().length > 0;
    }

    private byte[] getPsgPublicKeyForSignatureVerification(IPsgCertificateWithPubKey child)
        throws PsgCertificateException {
        return new PsgPublicKeyBuilder()
            .parse(child.getPsgPublicKey())
            .withActor(EndianessActor.FIRMWARE)
            .build()
            .array();
    }

    public boolean sigVerify(PsgCertificateCommon parent, PsgCertificateCommon child)
        throws PsgInvalidSignatureException {
        try {
            if (!(parent instanceof IPsgCertificateWithPubKey)
                || !(child instanceof IPsgCertificateWithPubKey)
                || !(child instanceof IPsgCertificateWithSignature)) {
                return false;
            }

            Signature signature =
                Signature.getInstance(getSignatureAlgorithm((IPsgCertificateWithPubKey) child),
                    CryptoUtils.getBouncyCastleProvider());
            signature.initVerify(decodeKey((IPsgCertificateWithPubKey) parent));
            signature.update(getPsgPublicKeyForSignatureVerification((IPsgCertificateWithPubKey) child));

            if (isSignatureInCertificate((IPsgCertificateWithSignature) child)) {
                PsgSignature psgSignature = parsePsgSignature((IPsgCertificateWithSignature) child);
                byte[] derSignature = convertToDerSignature(psgSignature.getSignatureR(), psgSignature.getSignatureS());
                return signature.verify(derSignature);
            } else {
                return false;
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException | SignatureException
                 | IOException | PsgCertificateException e) {
            throw new PsgInvalidSignatureException(FAILED_TO_CHECK_SIGNATURE, e);
        }
    }

    public static boolean sigVerify(String signatureAlgorithm, PublicKey publicKey, byte[] data,
                                    PsgSignatureBuilder signatureBuilder) throws PsgInvalidSignatureException {
        try {
            Signature ecdsaSign = Signature.getInstance(signatureAlgorithm, CryptoUtils.getBouncyCastleProvider());
            ecdsaSign.initVerify(publicKey);
            ecdsaSign.update(data);
            return ecdsaSign.verify(convertToDerSignature(signatureBuilder.getSignatureR(),
                signatureBuilder.getSignatureS()));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
            throw new PsgInvalidSignatureException(FAILED_TO_CHECK_SIGNATURE, e);
        }
    }

    static boolean sigVerify(X509Certificate certificate, byte[] data, byte[] signature)
        throws PsgInvalidSignatureException {
        try {
            Signature ecdsaSign = Signature.getInstance(CryptoConstants.SHA384_WITH_ECDSA,
                CryptoUtils.getBouncyCastleProvider());
            ecdsaSign.initVerify(certificate);
            ecdsaSign.update(data);
            return ecdsaSign.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new PsgInvalidSignatureException(FAILED_TO_CHECK_SIGNATURE, e);
        }
    }

    private String getSignatureAlgorithm(IPsgCertificateWithPubKey entry) throws PsgCertificateException {
        if (getCurveType(entry) == PsgCurveType.SECP384R1) {
            return CryptoConstants.SHA384_WITH_ECDSA;
        } else {
            return CryptoConstants.SHA256_WITH_ECDSA;
        }
    }

    private ECPublicKey decodeKey(IPsgCertificateWithPubKey parent)
        throws InvalidKeySpecException, NoSuchAlgorithmException, PsgCertificateException {
        return (ECPublicKey) PsgPublicKeyHelper.toPublic(parent.getPsgPublicKey());
    }

    private static PsgCurveType getCurveType(IPsgCertificateWithPubKey entry) throws PsgCertificateException {
        PsgPublicKey psgPublicKey = new PsgPublicKeyBuilder().parse(entry.getPsgPublicKey()).build();
        return PsgPublicKeyHelper.parseCurveType(psgPublicKey);
    }

    private static byte[] convertToDerSignature(byte[] partR, byte[] partS) throws IOException {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            ASN1OutputStream derOutputStream = ASN1OutputStream.create(byteArrayOutputStream, ASN1Encoding.DER);
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new ASN1Integer(new BigInteger(1, partR)));
            vector.add(new ASN1Integer(new BigInteger(1, partS)));
            derOutputStream.writeObject(new DERSequence(vector));
            return byteArrayOutputStream.toByteArray();
        }
    }

    public void verifyParentsInChainByPubKey(List<CertificateEntryWrapper> certificateChainList)
        throws PsgInvalidParentCertificatesException, PsgCertificateException, PsgInvalidSignatureException {

        Iterator<CertificateEntryWrapper> iterator = certificateChainList.iterator();
        if (iterator.hasNext() && !verifyParentsByPubKeyRecursive(iterator.next(), iterator)) {
            throw new PsgInvalidParentCertificatesException();
        }
    }
}
