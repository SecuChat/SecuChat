package models

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Base64Bytes is a []byte that is encoded on the wire as a base64 string.
//
// Go's encoding/json already marshals []byte as base64, but it will also accept
// JSON arrays when unmarshalling (because []byte is a slice). This type
// enforces the contract: API/WS binary fields must be base64 strings.
type Base64Bytes []byte

func (b Base64Bytes) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(b))
	return json.Marshal(encoded)
}

func (b *Base64Bytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = nil
		return nil
	}

	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("expected base64 string: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Allow unpadded standard base64 for interop.
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("invalid base64: %w", err)
		}
	}

	*b = Base64Bytes(decoded)
	return nil
}
