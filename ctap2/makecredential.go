package ctap2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"log"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/psanford/tpm-fido/attestation"
)

// MakeCredential handles the authenticatorMakeCredential command
func (h *Handler) MakeCredential(ctx context.Context, req *MakeCredentialRequest) (byte, []byte) {
	log.Printf("CTAP2 MakeCredential: RP=%s, User=%s", req.RP.ID, req.User.Name)

	// Validate clientDataHash
	if len(req.ClientDataHash) != 32 {
		log.Printf("CTAP2 MakeCredential: Invalid clientDataHash length: %d", len(req.ClientDataHash))
		return StatusInvalidParameter, nil
	}

	// Check if at least one supported algorithm is requested
	es256Supported := false
	for _, param := range req.PubKeyCredParams {
		if param.Type == CredentialTypePublicKey && param.Alg == COSEAlgES256 {
			es256Supported = true
			break
		}
	}
	if !es256Supported {
		log.Printf("CTAP2 MakeCredential: ES256 not in requested algorithms")
		return StatusUnsupportedExtension, nil // Actually should be unsupported algorithm
	}

	// Check excludeList for existing credentials
	rpIDHash := HashRPID(req.RP.ID)
	for _, excluded := range req.ExcludeList {
		// Try to verify if this credential exists by attempting to sign
		dummyHash := sha256.Sum256([]byte("exclude-check"))
		_, err := h.signer.SignASN1(excluded.ID, rpIDHash[:], dummyHash[:])
		if err == nil {
			// Credential exists and is valid - need user presence to confirm exclusion
			log.Printf("CTAP2 MakeCredential: Credential in excludeList exists")
			return StatusCredentialExcluded, nil
		}
	}

	// Request user presence
	var challengeParam, appParam [32]byte
	copy(challengeParam[:], req.ClientDataHash)
	copy(appParam[:], rpIDHash[:])

	pinResultCh, err := h.presence.ConfirmPresence("FIDO2 Confirm Register", challengeParam, appParam)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: user presence error: %s", err)
		return StatusOperationDenied, nil
	}

	// Wait for user response with timeout
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	select {
	case result := <-pinResultCh:
		if !result.OK {
			log.Printf("CTAP2 MakeCredential: User denied or error: %v", result.Error)
			return StatusOperationDenied, nil
		}
	case <-childCtx.Done():
		log.Printf("CTAP2 MakeCredential: User presence timeout")
		return StatusUserActionTimeout, nil
	}

	// Generate credential
	credentialID, x, y, err := h.signer.RegisterKey(rpIDHash[:])
	if err != nil {
		log.Printf("CTAP2 MakeCredential: RegisterKey error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 MakeCredential: Generated credential, ID length=%d", len(credentialID))

	// Build COSE public key
	coseKey, err := BuildCOSEPublicKeyES256(x, y)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: COSE key build error: %s", err)
		return StatusOther, nil
	}

	// Build extensions output if hmac-secret was requested
	var extensionsOutput []byte
	hmacSecretRequested := false
	if req.Extensions != nil {
		if _, ok := req.Extensions["hmac-secret"]; ok {
			hmacSecretRequested = true
			extMap := map[string]bool{"hmac-secret": true}
			extensionsOutput, _ = ctapEncMode.Marshal(extMap)
		}
	}

	// Build flags
	flags := byte(FlagUserPresent | FlagUserVerified | FlagAttestedCredData)
	if hmacSecretRequested {
		flags |= FlagExtensionData
	}

	// Build AuthenticatorData
	authData := &AuthenticatorData{
		RPIDHash:  rpIDHash,
		Flags:     flags,
		SignCount: h.signer.Counter(),
		AttestedCredentialData: &AttestedCredentialData{
			AAGUID:              h.aaguid,
			CredentialID:        credentialID,
			CredentialPublicKey: coseKey,
		},
		Extensions: extensionsOutput,
	}

	authDataBytes := authData.Marshal()

	// Build attestation signature: sign(authData || clientDataHash)
	toSign := append(authDataBytes, req.ClientDataHash...)
	sigHash := sha256.Sum256(toSign)

	sig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, sigHash[:])
	if err != nil {
		log.Printf("CTAP2 MakeCredential: Attestation sign error: %s", err)
		return StatusOther, nil
	}

	// Build attestation statement (packed format with x5c)
	attStmt := map[string]interface{}{
		"alg": COSEAlgES256,
		"sig": sig,
		"x5c": [][]byte{attestation.CertDer},
	}

	// Build response
	resp := &MakeCredentialResponse{
		Fmt:      "packed",
		AuthData: authDataBytes,
		AttStmt:  attStmt,
	}

	encoded, err := ctapEncMode.Marshal(resp)
	if err != nil {
		log.Printf("CTAP2 MakeCredential: Response encode error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 MakeCredential: Success, response=%d bytes", len(encoded))
	return StatusSuccess, encoded
}

// parseMakeCredentialRequest parses the CBOR-encoded MakeCredential request
func parseMakeCredentialRequest(data []byte) (*MakeCredentialRequest, error) {
	var req MakeCredentialRequest
	if err := cbor.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}
