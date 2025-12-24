package ctap2

// CTAP2 command bytes
const (
	CmdMakeCredential   = 0x01
	CmdGetAssertion     = 0x02
	CmdGetInfo          = 0x04
	CmdClientPIN        = 0x06
	CmdReset            = 0x07
	CmdGetNextAssertion = 0x08
	CmdSelection        = 0x0B
)

// CTAP2 status codes
const (
	StatusSuccess                = 0x00
	StatusInvalidCommand         = 0x01
	StatusInvalidParameter       = 0x02
	StatusInvalidLength          = 0x03
	StatusInvalidSeq             = 0x04
	StatusTimeout                = 0x05
	StatusChannelBusy            = 0x06
	StatusLockRequired           = 0x0A
	StatusInvalidChannel         = 0x0B
	StatusCBORUnexpectedType     = 0x11
	StatusInvalidCBOR            = 0x12
	StatusMissingParameter       = 0x14
	StatusLimitExceeded          = 0x15
	StatusUnsupportedExtension   = 0x16
	StatusCredentialExcluded     = 0x19
	StatusProcessing             = 0x21
	StatusInvalidCredential      = 0x22
	StatusUserActionPending      = 0x23
	StatusOperationPending       = 0x24
	StatusNoCredentials          = 0x2E
	StatusUserActionTimeout      = 0x2F
	StatusNotAllowed             = 0x30
	StatusPINInvalid             = 0x31
	StatusPINBlocked             = 0x32
	StatusPINAuthInvalid         = 0x33
	StatusPINAuthBlocked         = 0x34
	StatusPINNotSet              = 0x35
	StatusPINRequired            = 0x36
	StatusPINPolicyViolation     = 0x37
	StatusPINTokenExpired        = 0x38
	StatusRequestTooLarge        = 0x39
	StatusActionTimeout          = 0x3A
	StatusUpRequired             = 0x3B
	StatusUvBlocked              = 0x3C
	StatusKeepaliveCancel        = 0x2D
	StatusOperationDenied        = 0x27
	StatusOther                  = 0x7F
)

// COSE algorithm identifiers
const (
	COSEAlgES256 = -7   // ECDSA with SHA-256
	COSEAlgRS256 = -257 // RSASSA-PKCS1-v1_5 with SHA-256
	COSEAlgECDH  = -25  // ECDH-ES + HKDF-256 (used for key agreement)
)

// CTAP2 extension error codes
const (
	StatusExtensionFirst = 0xE0 // First extension-defined error
)

// COSE key type identifiers
const (
	COSEKeyTypeEC2 = 2 // Elliptic Curve
	COSEKeyTypeRSA = 3 // RSA
)

// COSE EC2 curve identifiers
const (
	COSECurveP256 = 1 // P-256 curve
)

// COSE key parameters
const (
	COSEKeyLabelKty = 1  // Key type
	COSEKeyLabelAlg = 3  // Algorithm
	COSEKeyLabelCrv = -1 // Curve (for EC2)
	COSEKeyLabelX   = -2 // X coordinate (for EC2)
	COSEKeyLabelY   = -3 // Y coordinate (for EC2)
)

// AuthenticatorData flags
const (
	FlagUserPresent       = 0x01 // UP
	FlagUserVerified      = 0x04 // UV
	FlagAttestedCredData  = 0x40 // AT
	FlagExtensionData     = 0x80 // ED
)

// Public key credential type
const (
	CredentialTypePublicKey = "public-key"
)
