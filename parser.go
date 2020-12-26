package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type (
	TokenUnmarshaller func(ctx CodingContext, data []byte, v interface{}) error

	// Parser is the type used to parse and validate a JWT token from string
	Parser struct {
		validAlgorithms      []string          // If populated, only these methods will be considered valid
		useJSONNumber        bool              // Use JSON Number format in JSON decoder
		skipClaimsValidation bool              // Skip claims validation during token parsing
		unmarshaller         TokenUnmarshaller // Use this instead of encoding/json
		*ValidationHelper
	}

	ParserOptions struct {
		Unmarshaller         TokenUnmarshaller
		ValidAlgorithms      []string
		JSONNumber           bool
		SkipClaimValidations bool
		AudienceValidation   bool
		Leeway               time.Duration
		Audience             string
		Issuer               string
	}
)

var DefaultParserOptions = ParserOptions{
	Unmarshaller:         nil,
	ValidAlgorithms:      nil,
	JSONNumber:           false,
	SkipClaimValidations: false,
	AudienceValidation:   false,
	Leeway:               0,
	Audience:             "",
	Issuer:               "",
}

// NewParser returns a new Parser with the specified options
func NewParser(options ...ParserOptions) *Parser {
	o := DefaultParserOptions

	if len(options) > 0 {
		o = options[0]
	}

	if o.AudienceValidation == false && o.Audience != "" {
		o.AudienceValidation = true
	}

	helper := &ValidationHelper{
		audienceValidation: o.AudienceValidation,
		issuer:       o.Issuer,
		audience:     o.Audience,
		leeway:       o.Leeway,
	}

	p := &Parser{
		validAlgorithms:      o.ValidAlgorithms,
		useJSONNumber:        o.JSONNumber,
		skipClaimsValidation: o.SkipClaimValidations,
		ValidationHelper:     helper,
		unmarshaller:         o.Unmarshaller,
	}
	return p
}

// Parse will parse, validate, and return a token.
// keyFunc will receive the parsed token and should return the key for validating.
// If everything is kosher, err will be nil
func (p *Parser) Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	return p.ParseWithClaims(tokenString, MapClaims{}, keyFunc)
}

// ParseWithClaims is just like parse, but with the claims type specified
func (p *Parser) ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc) (*Token, error) {
	token, parts, err := p.ParseUnverified(tokenString, claims)
	if err != nil {
		return token, err
	}

	// Verify signing method is in the required set
	if p.validAlgorithms != nil {
		signingMethodValid := false
		alg := token.Method.Alg()
		for _, m := range p.validAlgorithms {
			if m == alg {
				signingMethodValid = true
				break
			}
		}
		if !signingMethodValid {
			// signing method is not in the listed set
			return token, &UnverfiableTokenError{Message: fmt.Sprintf("signing method %v is invalid", alg)}
		}
	}

	// Lookup key
	var key interface{}
	if keyFunc == nil {
		// keyFunc was not provided.  short circuiting validation
		return token, &UnverfiableTokenError{Message: "no Keyfunc was provided."}
	}
	if key, err = keyFunc(token); err != nil {
		// keyFunc returned an error
		return token, wrapError(&UnverfiableTokenError{Message: "Keyfunc returned an error"}, err)
	}

	var vErr error

	// Perform validation
	token.Signature = parts[2]
	if err = token.Method.Verify(strings.Join(parts[0:2], "."), token.Signature, key); err != nil {
		vErr = wrapError(&InvalidSignatureError{}, err)
	}

	// Validate Claims
	if !p.skipClaimsValidation && vErr == nil {
		if err := token.Claims.Valid(p.ValidationHelper); err != nil {
			vErr = wrapError(err, vErr)
		}
	}

	if vErr == nil {
		token.Valid = true
	}

	return token, vErr
}

// ParseUnverified is used to inspect a token without validating it
// WARNING: Don't use this method unless you know what you're doing
//
// This method parses the token but doesn't validate the signature. It's only
// ever useful in cases where you know the signature is valid (because it has
// been checked previously in the stack) and you want to extract values from
// it. Or for debuggery.
func (p *Parser) ParseUnverified(tokenString string, claims Claims) (token *Token, parts []string, err error) {
	parts = strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, parts, &MalformedTokenError{Message: "token contains an invalid number of segments"}
	}

	token = &Token{Raw: tokenString}

	// choose unmarshaller
	unmarshaller := p.unmarshaller
	if unmarshaller == nil {
		unmarshaller = p.defaultUnmarshaller
	}

	// parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
			return token, parts, &MalformedTokenError{Message: "tokenstring should not contain 'bearer '"}
		}
		return token, parts, wrapError(&MalformedTokenError{Message: "failed to decode token header"}, err)
	}
	if err = unmarshaller(CodingContext{HeaderFieldDescriptor, nil}, headerBytes, &token.Header); err != nil {
		return token, parts, wrapError(&MalformedTokenError{Message: "failed to unmarshal token header"}, err)
	}

	// parse Claims
	var claimBytes []byte
	token.Claims = claims

	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return token, parts, wrapError(&MalformedTokenError{Message: "failed to decode token claims"}, err)
	}
	// JSON Decode.  Special case for map type to avoid weird pointer behavior
	ctx := CodingContext{ClaimsFieldDescriptor, token.Header}
	if c, ok := token.Claims.(MapClaims); ok {
		err = unmarshaller(ctx, claimBytes, &c)
	} else {
		err = unmarshaller(ctx, claimBytes, &claims)
	}
	// Handle decode error
	if err != nil {
		return token, parts, wrapError(&MalformedTokenError{Message: "failed to unmarshal token claims"}, err)
	}

	// Lookup signature method
	if method, ok := token.Header["alg"].(string); ok {
		if token.Method = GetSigningMethod(method); token.Method == nil {
			return token, parts, &UnverfiableTokenError{Message: "signing method (alg) is unavailable."}
		}
	} else {
		return token, parts, &UnverfiableTokenError{Message: "signing method (alg) is unspecified."}
	}

	return token, parts, nil
}

func (p *Parser) defaultUnmarshaller(ctx CodingContext, data []byte, v interface{}) error {
	// If we don't need a special parser, use Unmarshal
	// We never use a special encoder for the header
	if !p.useJSONNumber || ctx.FieldDescriptor == HeaderFieldDescriptor {
		return json.Unmarshal(data, v)
	}

	// To enable the JSONNumber mode, we must use Decoder instead of Unmarshal
	dec := json.NewDecoder(bytes.NewBuffer(data))
	dec.UseNumber()
	return dec.Decode(v)
}
