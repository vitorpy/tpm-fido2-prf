package ctap2

// GetInfoResponse is the response to authenticatorGetInfo (0x04)
// CTAP2 uses integer keys in CBOR maps
type GetInfoResponse struct {
	Versions                    []string          `cbor:"1,keyasint"`
	Extensions                  []string          `cbor:"2,keyasint,omitempty"`
	AAGUID                      []byte            `cbor:"3,keyasint"`
	Options                     map[string]bool   `cbor:"4,keyasint,omitempty"`
	MaxMsgSize                  uint              `cbor:"5,keyasint,omitempty"`
	PinUvAuthProtocols          []uint            `cbor:"6,keyasint,omitempty"`
	MaxCredentialCountInList    uint              `cbor:"7,keyasint,omitempty"`
	MaxCredentialIdLength       uint              `cbor:"8,keyasint,omitempty"`
	Transports                  []string          `cbor:"9,keyasint,omitempty"`
	Algorithms                  []PublicKeyCredentialParameters `cbor:"10,keyasint,omitempty"`
	MaxSerializedLargeBlobArray uint              `cbor:"11,keyasint,omitempty"`
	ForcePINChange              bool              `cbor:"12,keyasint,omitempty"`
	MinPINLength                uint              `cbor:"13,keyasint,omitempty"`
	FirmwareVersion             uint              `cbor:"14,keyasint,omitempty"`
	MaxCredBlobLength           uint              `cbor:"15,keyasint,omitempty"`
	MaxRPIDsForSetMinPINLength  uint              `cbor:"16,keyasint,omitempty"`
	PreferredPlatformUvAttempts uint              `cbor:"17,keyasint,omitempty"`
	UvModality                  uint              `cbor:"18,keyasint,omitempty"`
	Certifications              map[string]int    `cbor:"19,keyasint,omitempty"`
	RemainingDiscoverableCredentials int          `cbor:"20,keyasint,omitempty"`
	VendorPrototypeConfigCommands []uint          `cbor:"21,keyasint,omitempty"`
}

// PublicKeyCredentialParameters specifies a credential type and algorithm
type PublicKeyCredentialParameters struct {
	Type string `cbor:"type"`
	Alg  int    `cbor:"alg"`
}

// PublicKeyCredentialRpEntity represents the relying party
type PublicKeyCredentialRpEntity struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name,omitempty"`
}

// PublicKeyCredentialUserEntity represents the user
type PublicKeyCredentialUserEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
}

// PublicKeyCredentialDescriptor identifies a credential
type PublicKeyCredentialDescriptor struct {
	Type       string   `cbor:"type"`
	ID         []byte   `cbor:"id"`
	Transports []string `cbor:"transports,omitempty"`
}

// MakeCredentialRequest is the request for authenticatorMakeCredential (0x01)
type MakeCredentialRequest struct {
	ClientDataHash    []byte                          `cbor:"1,keyasint"`
	RP                PublicKeyCredentialRpEntity     `cbor:"2,keyasint"`
	User              PublicKeyCredentialUserEntity   `cbor:"3,keyasint"`
	PubKeyCredParams  []PublicKeyCredentialParameters `cbor:"4,keyasint"`
	ExcludeList       []PublicKeyCredentialDescriptor `cbor:"5,keyasint,omitempty"`
	Extensions        map[string]interface{}          `cbor:"6,keyasint,omitempty"`
	Options           map[string]bool                 `cbor:"7,keyasint,omitempty"`
	PinUvAuthParam    []byte                          `cbor:"8,keyasint,omitempty"`
	PinUvAuthProtocol uint                            `cbor:"9,keyasint,omitempty"`
	EnterpriseAttestation uint                        `cbor:"10,keyasint,omitempty"`
}

// MakeCredentialResponse is the response for authenticatorMakeCredential
type MakeCredentialResponse struct {
	Fmt      string                 `cbor:"1,keyasint"`
	AuthData []byte                 `cbor:"2,keyasint"`
	AttStmt  map[string]interface{} `cbor:"3,keyasint"`
}

// GetAssertionRequest is the request for authenticatorGetAssertion (0x02)
type GetAssertionRequest struct {
	RPID              string                          `cbor:"1,keyasint"`
	ClientDataHash    []byte                          `cbor:"2,keyasint"`
	AllowList         []PublicKeyCredentialDescriptor `cbor:"3,keyasint,omitempty"`
	Extensions        map[string]interface{}          `cbor:"4,keyasint,omitempty"`
	Options           map[string]bool                 `cbor:"5,keyasint,omitempty"`
	PinUvAuthParam    []byte                          `cbor:"6,keyasint,omitempty"`
	PinUvAuthProtocol uint                            `cbor:"7,keyasint,omitempty"`
}

// GetAssertionResponse is the response for authenticatorGetAssertion
type GetAssertionResponse struct {
	Credential          *PublicKeyCredentialDescriptor `cbor:"1,keyasint,omitempty"`
	AuthData            []byte                         `cbor:"2,keyasint"`
	Signature           []byte                         `cbor:"3,keyasint"`
	User                *PublicKeyCredentialUserEntity `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials uint                           `cbor:"5,keyasint,omitempty"`
}

// COSEKey represents a COSE_Key structure for key agreement
type COSEKey struct {
	Kty int    `cbor:"1,keyasint"`           // Key type (2 = EC2)
	Alg int    `cbor:"3,keyasint,omitempty"` // Algorithm
	Crv int    `cbor:"-1,keyasint"`          // Curve (1 = P-256)
	X   []byte `cbor:"-2,keyasint"`          // X coordinate
	Y   []byte `cbor:"-3,keyasint"`          // Y coordinate
}

// HmacSecretInput is the extension input for hmac-secret on GetAssertion
type HmacSecretInput struct {
	KeyAgreement      COSEKey `cbor:"1,keyasint"` // Platform's ephemeral public key
	SaltEnc           []byte  `cbor:"2,keyasint"` // Encrypted salt(s): 32 or 64 bytes
	SaltAuth          []byte  `cbor:"3,keyasint"` // HMAC-SHA-256(sharedSecret, saltEnc)[:16]
	PinUvAuthProtocol uint    `cbor:"4,keyasint,omitempty"`
}

// ClientPINRequest is the request for authenticatorClientPIN (0x06)
type ClientPINRequest struct {
	PinUvAuthProtocol uint    `cbor:"1,keyasint,omitempty"`
	SubCommand        uint    `cbor:"2,keyasint"`
	KeyAgreement      *COSEKey `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte  `cbor:"4,keyasint,omitempty"`
	NewPinEnc         []byte  `cbor:"5,keyasint,omitempty"`
	PinHashEnc        []byte  `cbor:"6,keyasint,omitempty"`
	Permissions       uint    `cbor:"9,keyasint,omitempty"`
	PermissionsRPID   string  `cbor:"10,keyasint,omitempty"`
}

// ClientPINResponse is the response for authenticatorClientPIN
type ClientPINResponse struct {
	KeyAgreement    *COSEKey `cbor:"1,keyasint,omitempty"`
	PinUvAuthToken  []byte   `cbor:"2,keyasint,omitempty"`
	PinRetries      uint     `cbor:"3,keyasint,omitempty"`
	PowerCycleState bool     `cbor:"4,keyasint,omitempty"`
	UvRetries       uint     `cbor:"5,keyasint,omitempty"`
}

// ClientPIN subcommands
const (
	ClientPINSubCmdGetPINRetries         = 0x01
	ClientPINSubCmdGetKeyAgreement       = 0x02
	ClientPINSubCmdSetPIN                = 0x03
	ClientPINSubCmdChangePIN             = 0x04
	ClientPINSubCmdGetPINToken           = 0x05
	ClientPINSubCmdGetPINUvAuthTokenUsingUvWithPermissions = 0x06
	ClientPINSubCmdGetUVRetries          = 0x07
	ClientPINSubCmdGetPINUvAuthTokenUsingPinWithPermissions = 0x09
)
