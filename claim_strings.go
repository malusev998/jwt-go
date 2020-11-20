package jwt

import (
	"encoding/json"
	"reflect"
)

// ClaimStrings is used for parsing claim properties that
// can be either a string or array of strings
type ClaimStrings []string

// ParseClaimStrings is used to produce a ClaimStrings value
// from the various forms it may present during encoding/decoding
func ParseClaimStrings(value interface{}) (ClaimStrings, error) {
	switch v := value.(type) {
	case string:
		return ClaimStrings{v}, nil
	case []string:
		return v, nil
	case nil:
		return nil, nil
	default:
		return nil, &json.UnsupportedTypeError{Type: reflect.TypeOf(v)}
	}
}

// UnmarshalJSON implements the json package's Unmarshaler interface
func (c *ClaimStrings) UnmarshalJSON(data []byte) (err error) {
	var value interface{}
	err = json.Unmarshal(data, &value)
	if err != nil {
		return err
	}

	*c, err = ParseClaimStrings(value)
	return err
}
