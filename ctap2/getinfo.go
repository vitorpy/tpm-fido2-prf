package ctap2

// GetInfo returns the authenticator capabilities
func (h *Handler) GetInfo() *GetInfoResponse {
	return &GetInfoResponse{
		// Supported protocol versions
		Versions: []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1"},

		// Supported extensions
		Extensions: []string{"hmac-secret"},

		// Authenticator identifier
		AAGUID: h.aaguid[:],

		// Authenticator options
		Options: map[string]bool{
			"rk":   false, // Resident keys not supported (no persistent storage)
			"up":   true,  // User presence supported via fingerprint
			"uv":   true,  // User verification via fingerprint (enables hmac-secret without PIN)
			"plat": false, // Not a platform authenticator
		},

		// Maximum message size
		MaxMsgSize: 1200,

		// Supported PIN/UV auth protocols
		// Protocol 1 is needed for hmac-secret even without PIN
		PinUvAuthProtocols: []uint{1},

		// Maximum credentials in allowList/excludeList
		MaxCredentialCountInList: 8,

		// Maximum credential ID length
		MaxCredentialIdLength: 128,

		// Supported transports
		Transports: []string{"usb"},

		// Supported algorithms
		Algorithms: []PublicKeyCredentialParameters{
			{
				Type: CredentialTypePublicKey,
				Alg:  COSEAlgES256, // -7 = ES256 (ECDSA with P-256 and SHA-256)
			},
		},
	}
}
