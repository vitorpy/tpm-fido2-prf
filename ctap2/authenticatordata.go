package ctap2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// AuthenticatorData builds the authenticator data structure for CTAP2 responses
type AuthenticatorData struct {
	RPIDHash               [32]byte
	Flags                  byte
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             []byte // CBOR-encoded extensions
}

// AttestedCredentialData contains the credential information for MakeCredential
type AttestedCredentialData struct {
	AAGUID              [16]byte
	CredentialID        []byte
	CredentialPublicKey []byte // COSE-encoded public key
}

// Marshal serializes the AuthenticatorData to bytes
func (ad *AuthenticatorData) Marshal() []byte {
	var buf bytes.Buffer

	// rpIdHash (32 bytes)
	buf.Write(ad.RPIDHash[:])

	// flags (1 byte)
	buf.WriteByte(ad.Flags)

	// signCount (4 bytes, big-endian)
	binary.Write(&buf, binary.BigEndian, ad.SignCount)

	// attestedCredentialData (if AT flag is set)
	if ad.Flags&FlagAttestedCredData != 0 && ad.AttestedCredentialData != nil {
		acd := ad.AttestedCredentialData

		// aaguid (16 bytes)
		buf.Write(acd.AAGUID[:])

		// credentialIdLength (2 bytes, big-endian)
		binary.Write(&buf, binary.BigEndian, uint16(len(acd.CredentialID)))

		// credentialId
		buf.Write(acd.CredentialID)

		// credentialPublicKey (COSE-encoded)
		buf.Write(acd.CredentialPublicKey)
	}

	// extensions (if ED flag is set)
	if ad.Flags&FlagExtensionData != 0 && len(ad.Extensions) > 0 {
		buf.Write(ad.Extensions)
	}

	return buf.Bytes()
}

// HashRPID returns the SHA-256 hash of an RP ID
func HashRPID(rpID string) [32]byte {
	return sha256.Sum256([]byte(rpID))
}

// BuildCOSEPublicKeyES256 builds a COSE_Key for ES256 (P-256) from X, Y coordinates
// COSE Key format:
//
//	{
//	  1: 2,      // kty: EC2
//	  3: -7,     // alg: ES256
//	  -1: 1,     // crv: P-256
//	  -2: x,     // x coordinate (32 bytes)
//	  -3: y      // y coordinate (32 bytes)
//	}
func BuildCOSEPublicKeyES256(x, y *big.Int) ([]byte, error) {
	// Pad X and Y to 32 bytes
	xBytes := padTo32(x.Bytes())
	yBytes := padTo32(y.Bytes())

	// Build the COSE key as a map
	coseKey := map[int]interface{}{
		1:  2,       // kty: EC2
		3:  -7,      // alg: ES256
		-1: 1,       // crv: P-256
		-2: xBytes,  // x coordinate
		-3: yBytes,  // y coordinate
	}

	return ctapEncMode.Marshal(coseKey)
}

// padTo32 pads a byte slice to 32 bytes (for EC point coordinates)
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
