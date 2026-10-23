package certdb

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// jvmFingerprints returns the SHA-256 fingerprints (uppercase hex) that a JDK
// blocked.certs file must list to block a certificate, as OpenJDK's
// BlockedCertsConverter computes them. The JVM hashes a certificate exactly as
// it receives it, so the list covers re-encodings that are still valid: the
// signature algorithm parameters with and without NULL, and for ECDSA
// signatures both s and n-s.
func jvmFingerprints(der []byte) ([]string, error) {
	var cert struct {
		TBS       asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &cert)
	if err != nil || len(rest) > 0 {
		return nil, errors.New("not a DER certificate")
	}

	var algorithm pkix.AlgorithmIdentifier
	if _, err = asn1.Unmarshal(cert.Algorithm.FullBytes, &algorithm); err != nil {
		return nil, fmt.Errorf("read signature algorithm: %w", err)
	}
	// Absent parameters become NULL, and present ones are dropped.
	alternative := pkix.AlgorithmIdentifier{Algorithm: algorithm.Algorithm}
	if len(algorithm.Parameters.FullBytes) == 0 {
		alternative.Parameters = asn1.NullRawValue
	}
	alternativeAlgorithm, err := asn1.Marshal(alternative)
	if err != nil {
		return nil, fmt.Errorf("encode signature algorithm: %w", err)
	}

	signature, err := asn1.Marshal(cert.Signature)
	if err != nil {
		return nil, fmt.Errorf("encode signature: %w", err)
	}
	signatures := [][]byte{signature}
	if isECDSA(algorithm.Algorithm) {
		malleable, malleableErr := negatedECDSASignature(cert.Signature.Bytes)
		if malleableErr != nil {
			return nil, malleableErr
		}
		signatures = append(signatures, malleable)
	}

	var fingerprints []string
	for _, algorithmBytes := range [][]byte{cert.Algorithm.FullBytes, alternativeAlgorithm} {
		for _, signatureBytes := range signatures {
			encoding, marshalErr := asn1.Marshal(asn1.RawValue{
				Tag:        asn1.TagSequence,
				IsCompound: true,
				Bytes:      concat(cert.TBS.FullBytes, algorithmBytes, signatureBytes),
			})
			if marshalErr != nil {
				return nil, fmt.Errorf("encode certificate: %w", marshalErr)
			}
			sum := sha256.Sum256(encoding)
			fingerprints = append(fingerprints, strings.ToUpper(hex.EncodeToString(sum[:])))
		}
	}
	return fingerprints, nil
}

// isECDSA reports whether an algorithm OID is one of ecdsa-with-SHA*
// (1.2.840.10045.4.3.x).
func isECDSA(oid asn1.ObjectIdentifier) bool {
	return len(oid) == 7 && oid[:6].Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3})
}

// negatedECDSASignature returns the BIT STRING of the equally valid ECDSA
// signature (r, n-s). The curve follows from the signature length, as in
// BlockedCertsConverter.
func negatedECDSASignature(signature []byte) ([]byte, error) {
	var curve elliptic.Curve
	switch length := len(signature); {
	case length >= 68 && length <= 72:
		curve = elliptic.P256()
	case length >= 100 && length <= 104:
		curve = elliptic.P384()
	case length >= 135 && length <= 139:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unrecognized ECDSA signature length %d", length)
	}
	var value struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(signature, &value); err != nil {
		return nil, fmt.Errorf("read ECDSA signature: %w", err)
	}
	order := curve.Params().N
	value.S = new(big.Int).Mod(new(big.Int).Neg(value.S), order)
	encoded, err := asn1.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode ECDSA signature: %w", err)
	}
	const bitsPerByte = 8
	return asn1.Marshal(asn1.BitString{Bytes: encoded, BitLength: len(encoded) * bitsPerByte})
}

func concat(parts ...[]byte) []byte {
	var joined []byte
	for _, part := range parts {
		joined = append(joined, part...)
	}
	return joined
}
