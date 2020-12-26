package jwt_test

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/malusev998/jwt-go/v4"
	"github.com/malusev998/jwt-go/v4/test"
	"golang.org/x/xerrors"
)

var keyFuncError = fmt.Errorf("error loading key")

var (
	jwtTestDefaultKey *rsa.PublicKey
	defaultKeyFunc    jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return jwtTestDefaultKey, nil }
	emptyKeyFunc      jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, nil }
	errorKeyFunc      jwt.Keyfunc = func(t *jwt.Token) (interface{}, error) { return nil, keyFuncError }
	nilKeyFunc        jwt.Keyfunc = nil
)

func init() {
	jwtTestDefaultKey = test.LoadRSAPublicKeyFromDisk("test/sample_key.pub")
}

var jwtTestData = []struct {
	name        string
	tokenString string
	keyfunc     jwt.Keyfunc
	claims      jwt.Claims
	valid       bool
	errors      []error
	parser      *jwt.Parser
}{
	{
		name:        "basic",
		tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar"},
		valid:       true,
		errors:      nil,
		parser:      nil,
	},
	{
		name:        "basic expired",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		valid:       false,
		errors:      []error{&jwt.TokenExpiredError{}},
		parser:      nil,
	},
	{
		name:        "basic nbf",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100)},
		valid:       false,
		errors:      []error{&jwt.TokenNotValidYetError{}},
		parser:      nil,
	},
	{
		name:        "expired and nbf",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100), "exp": float64(time.Now().Unix() - 100)},
		valid:       false,
		errors:      []error{&jwt.TokenExpiredError{}, &jwt.TokenNotValidYetError{}},
		parser:      nil,
	},
	{
		name:        "expired and nbf with leeway",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 50), "exp": float64(time.Now().Unix() - 50)},
		valid:       true,
		errors:      nil,
		parser:      jwt.NewParser(jwt.ParserOptions{Leeway: 100 * time.Second}),
	},
	{
		name:        "basic invalid",
		tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar"},
		valid:       false,
		errors:      []error{&jwt.InvalidSignatureError{}},
		parser:      nil,
	},
	{
		name:        "basic nokeyfunc",
		tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfunc:     nilKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar"},
		valid:       false,
		errors:      []error{&jwt.UnverfiableTokenError{}},
		parser:      nil,
	},
	{
		name:        "basic nokey",
		tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfunc:     emptyKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar"},
		valid:       false,
		errors:      []error{&jwt.InvalidSignatureError{}},
		parser:      nil,
	},
	{
		name:        "basic errorkey",
		tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		keyfunc:     errorKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar"},
		valid:       false,
		errors:      []error{&jwt.UnverfiableTokenError{}},
		parser:      nil,
	},
	{
		name:        "invalid signing method",
		tokenString: "",
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar"},
		valid:       false,
		errors:      []error{&jwt.InvalidSignatureError{}},
		parser:      jwt.NewParser(jwt.ParserOptions{ValidAlgorithms: []string{"HS256"}}),
	},
	{
		name:        "valid signing method",
		tokenString: "",
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar"},
		valid:       true,
		errors:      nil,
		parser:      jwt.NewParser(jwt.ParserOptions{ValidAlgorithms: []string{"RS256", "HS256"}}),
	},
	{
		name:        "JSON Number",
		tokenString: "",
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": json.Number("123.4")},
		valid:       true,
		errors:      nil,
		parser:      jwt.NewParser(jwt.ParserOptions{JSONNumber: true}),
	},
	{
		name:        "Standard Claims",
		tokenString: "",
		keyfunc:     defaultKeyFunc,
		claims: &jwt.StandardClaims{
			ExpiresAt: jwt.At(time.Now().Add(time.Second * 10).Truncate(time.Second)),
		},
		valid:  true,
		errors: nil,
		parser: jwt.NewParser(jwt.ParserOptions{JSONNumber: true}),
	},
	{
		name:        "JSON Number - basic expired",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar", "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		valid:       false,
		errors:      []error{&jwt.TokenExpiredError{}},
		parser:      jwt.NewParser(jwt.ParserOptions{JSONNumber: true}),
	},
	{
		name:        "JSON Number - basic nbf",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		valid:       false,
		errors:      []error{&jwt.TokenNotValidYetError{}},
		parser:      jwt.NewParser(jwt.ParserOptions{JSONNumber: true}),
	},
	{
		name:        "JSON Number - expired and nbf",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100)), "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		valid:       false,
		errors:      []error{&jwt.TokenExpiredError{}, &jwt.TokenNotValidYetError{}},
		parser:      jwt.NewParser(jwt.ParserOptions{JSONNumber: true}),
	},
	{
		name:        "SkipClaimsValidation during token parsing",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		valid:       true,
		errors:      nil,
		parser:      jwt.NewParser(jwt.ParserOptions{JSONNumber: true, SkipClaimValidations: true}),
	},
	{
		name:        "Audience - Required",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"aud": []interface{}{"foo", "bar"}},
		valid:       false,
		errors:      []error{&jwt.InvalidAudienceError{Message: "audience value was expected but not provided"}},
		parser:      jwt.NewParser(jwt.ParserOptions{AudienceValidation: true}),
	},
	{
		name:        "Audience - Fail",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"aud": []interface{}{"foo", "bar"}},
		valid:       false,
		errors:      []error{&jwt.InvalidAudienceError{}},
		parser:      jwt.NewParser(jwt.ParserOptions{Audience: "baz"}),
	},
	{
		name:        "Issuer - Pass",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"iss": "foo"},
		valid:       true,
		errors:      nil,
		parser:      jwt.NewParser(jwt.ParserOptions{Issuer: "foo"}),
	},
	{
		name:        "Issuer - Fail",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"iss": "foo"},
		valid:       false,
		errors:      []error{&jwt.InvalidIssuerError{}},
		parser:      jwt.NewParser(jwt.ParserOptions{Issuer: "bar"}),
	},
	{
		name:        "Issuer - Provided but not in claims",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{},
		valid:       false,
		errors:      []error{&jwt.InvalidIssuerError{}},
		parser:      jwt.NewParser(jwt.ParserOptions{Issuer: "bar"}),
	},
	{
		name:        "Issuer - Ignored",
		tokenString: "", // autogen
		keyfunc:     defaultKeyFunc,
		claims:      jwt.MapClaims{"iss": "foo"},
		valid:       true,
		errors:      nil,
		parser:      jwt.NewParser(),
	},
}

func TestParser_Parse(t *testing.T) {
	t.Parallel()
	privateKey := test.LoadRSAPrivateKeyFromDisk("test/sample_key")

	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		// If the token string is blank, use helper function to generate string
		if data.tokenString == "" {
			data.tokenString = test.MakeSampleToken(data.claims, privateKey)
		}

		// Parse the token
		var token *jwt.Token
		var err error
		var parser = data.parser
		if parser == nil {
			parser = new(jwt.Parser)
		}
		// Figure out correct claims type
		switch data.claims.(type) {
		case jwt.MapClaims:
			token, err = parser.ParseWithClaims(data.tokenString, jwt.MapClaims{}, data.keyfunc)
		case *jwt.StandardClaims:
			token, err = parser.ParseWithClaims(data.tokenString, &jwt.StandardClaims{}, data.keyfunc)
		}

		// Verify result matches expectation
		if !reflect.DeepEqual(data.claims, token.Claims) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
		}

		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
		}

		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid token passed validation", data.name)
		}

		if (err == nil && !token.Valid) || (err != nil && token.Valid) {
			t.Errorf("[%v] Inconsistent behavior between returned error and token.Valid", data.name)
		}

		if data.errors != nil {
			if err == nil {
				t.Errorf("[%v] Expecting error.  Didn't get one.", data.name)
			} else {
				for _, expected := range data.errors {
					var xxx error = expected
					if !xerrors.As(err, &xxx) {
						t.Errorf("[%v] Error is expected to match type %T but doesn't", data.name, expected)
					}
				}
			}
		}
		if data.valid && token.Signature == "" {
			t.Errorf("[%v] Signature is left unpopulated after parsing", data.name)
		}
	}
}

func TestParser_ParseUnverified(t *testing.T) {
	t.Parallel()
	privateKey := test.LoadRSAPrivateKeyFromDisk("test/sample_key")

	// Iterate over test data set and run tests
	for _, data := range jwtTestData {
		// If the token string is blank, use helper function to generate string
		if data.tokenString == "" {
			data.tokenString = test.MakeSampleToken(data.claims, privateKey)
		}

		// Parse the token
		var token *jwt.Token
		var err error
		var parser = data.parser
		if parser == nil {
			parser = new(jwt.Parser)
		}
		// Figure out correct claims type
		switch data.claims.(type) {
		case jwt.MapClaims:
			token, _, err = parser.ParseUnverified(data.tokenString, jwt.MapClaims{})
		case *jwt.StandardClaims:
			token, _, err = parser.ParseUnverified(data.tokenString, &jwt.StandardClaims{})
		}

		if err != nil {
			t.Errorf("[%v] Invalid token", data.name)
		}

		// Verify result matches expectation
		if !reflect.DeepEqual(data.claims, token.Claims) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", data.name, data.claims, token.Claims)
		}

		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
		}
	}
}

// Helper method for benchmarking various methods
func benchmarkSigning(b *testing.B, method jwt.SigningMethod, key interface{}) {
	t := jwt.New(method)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := t.SignedString(key); err != nil {
				b.Fatal(err)
			}
		}
	})

}
