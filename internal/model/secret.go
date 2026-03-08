package model

import (
	"time"

	"github.com/google/uuid"
)

// Secret holds a versioned encrypted blob for a project/environment.
// Ciphertext, Nonce, and AuthTag are never serialized to JSON.
type Secret struct {
	ID              uuid.UUID  `db:"id"                json:"id"`
	ProjectID       uuid.UUID  `db:"project_id"        json:"project_id"`
	Environment     string     `db:"environment"       json:"environment"`
	Ciphertext      []byte     `db:"ciphertext"        json:"-"`
	Nonce           []byte     `db:"nonce"             json:"-"`
	AuthTag         []byte     `db:"auth_tag"          json:"-"`
	PushedBy        *uuid.UUID `db:"pushed_by"         json:"pushed_by,omitempty"`
	PushedByMachine *uuid.UUID `db:"pushed_by_machine" json:"pushed_by_machine,omitempty"`
	Version         int        `db:"version"           json:"version"`
	BaseVersion     *int       `db:"base_version"      json:"base_version,omitempty"`
	PushMessage     *string    `db:"push_message"      json:"push_message,omitempty"`
	KeyCount        int        `db:"key_count"         json:"key_count"`
	Checksum        string     `db:"checksum"          json:"checksum"`
	CreatedAt       time.Time  `db:"created_at"        json:"created_at"`
}

// SecretRecipient holds the per-recipient encrypted AES key for a secret version.
// EncryptedAESKey and related fields are never serialized to JSON.
type SecretRecipient struct {
	ID              uuid.UUID  `db:"id"                json:"id"`
	SecretID        uuid.UUID  `db:"secret_id"         json:"secret_id"`
	IdentityType    string     `db:"identity_type"     json:"identity_type"` // "user" or "machine"
	UserID          *uuid.UUID `db:"user_id"           json:"user_id,omitempty"`
	MachineID       *uuid.UUID `db:"machine_id"        json:"machine_id,omitempty"`
	KeyFingerprint  string     `db:"key_fingerprint"   json:"key_fingerprint"`
	EncryptedAESKey []byte     `db:"encrypted_aes_key" json:"-"`
	// Ed25519/X25519 hybrid encryption fields:
	EphemeralPublic []byte `db:"ephemeral_public" json:"-"`
	KeyNonce        []byte `db:"key_nonce"        json:"-"`
	KeyAuthTag      []byte `db:"key_auth_tag"     json:"-"`
}
