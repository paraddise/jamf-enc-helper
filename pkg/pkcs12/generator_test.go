package pkcs12

import (
	"crypto/sha256"
	"reflect"
	"testing"
)

func intsToBytes(ints []int) []byte {
	bytes := make([]byte, len(ints))
	for i, v := range ints {
		if v < 0 {
			bytes[i] = byte(256 + v)
		} else {
			bytes[i] = byte(v)
		}
	}
	return bytes
}

func TestMatchWithBouncyCastle(t *testing.T) {
	var testCases = []struct {
		pass       string
		salt       []int
		iterations int
		resultKey  []int
		resultIV   []int
	}{
		{
			pass:       "2M#84->)y^%2kGmN97ZLfhbL|-M:j?",
			salt:       []int{-87, -101, -56, 50, 86, 53, -29, 3},
			iterations: 19,
			resultKey:  []int{115, 15, 48, -33, 15, 80, -95, 49, 13, -32, -126, 33, -15, 37, 69, -60, 123, -30, 83, 42, -25, -34, -44, -67, 24, -62, -33, -93, -31, -78, 23, 57},
			resultIV:   []int{-4, 14, 113, -3, -100, -35, -48, -55, 32, 49, -75, -26, -60, 56, -2, -126},
		},
		{
			pass:       "test",
			salt:       []int{},
			iterations: 1024,
			resultKey:  []int{67, -107, 35, -49, -51, 80, -25, 84, -105, -5, -37, -90, -13, -38, 43, 26, -106, -60, -44, -54, -36, -17, -108, -108, 61, -28, -19, -10, 26, -50, -68, 68},
			resultIV:   []int{-23, 8, 45, -119, 14, 33, 126, -3, 123, 51, 107, 75, 67, 96, -77, 54},
		},
		{
			pass:       "hello",
			salt:       []int{},
			iterations: 1000,
			resultKey:  []int{119, 97, -40, 111, 103, 85, 115, 42, 38, 10, 19, -87, -24, -5, 104, 81, 109, 8, -82, 108, -118, 127, 122, 80, -88, 34, -11, -113, 82, 5, -9, -30},
			resultIV:   []int{95, 27, -105, 98, 109, -110, 91, -119, -92, 103, -78, -13, 58, -8, -42, -117},
		},
		{
			pass:       "password123",
			salt:       []int{1, 2, 3, 4},
			iterations: 10,
			resultKey:  []int{97, -79, -2, -3, 22, -117, 42, 82, 116, -62, -105, 29, -63, -10, -109, 109, 0, 113, 21, 26, -124, -112, 103, 12, 73, -58, -91, 116, -109, -64, -94, 42},
			resultIV:   []int{-52, 41, 104, -100, 89, -106, 62, 87, 87, 40, 120, 37, 55, 38, 126, 98},
		},
		{
			pass:       "",
			salt:       []int{},
			iterations: 1024,
			resultKey:  []int{65, -46, 4, 86, 27, 112, 99, -89, -92, 19, 37, 63, 35, -82, 77, 8, -128, 93, -61, 41, -26, 86, -120, 9, 91, -17, -113, 15, -39, -78, 59, 125},
			resultIV:   []int{-56, -105, -88, 41, -86, -73, -123, -73, -122, 73, 120, 91, -12, -47, -104, -108},
		},
		{
			pass:       "ThisIsAVeryLongPasswordForTestingPurposes",
			salt:       []int{-1, -2, -3, -4},
			iterations: 50,
			resultKey:  []int{-22, 93, -76, -11, -4, 52, -41, -12, 12, -43, 117, -34, -4, 30, -14, 65, -72, -31, 50, -10, -12, -52, 92, 22, -120, -104, -82, -2, 2, -42, 109, -94},
			resultIV:   []int{-108, 68, 107, 125, -13, 2, 20, -114, 14, 48, -32, 37, 17, 17, -91, 70},
		},
		{
			pass:       "!@#$%^&*()",
			salt:       []int{},
			iterations: 256,
			resultKey:  []int{-81, 60, 31, -35, 103, -89, -24, -35, 122, -17, 51, 62, -18, -74, 42, -50, 101, 20, -63, 56, 42, -41, -99, -26, 5, -127, -67, 6, -3, 91, -126, -13},
			resultIV:   []int{5, 5, 125, 57, 75, -91, -64, -25, -47, -16, -82, 34, -106, -6, 94, 121},
		},
		{
			pass:       "测试密码",
			salt:       []int{},
			iterations: 1024,
			resultKey:  []int{-1, -99, -127, 7, 32, -126, 26, -59, -126, -80, -71, 70, -53, 64, 109, -43, 55, 111, 46, 71, -115, -125, -56, 96, -116, 92, -87, 24, -67, 87, -18, 68},
			resultIV:   []int{66, 73, 113, -78, 27, 81, -97, 57, 90, 65, 33, -76, 121, -38, 63, -77},
		},
	}

	for _, testCase := range testCases {
		keyInBytes := intsToBytes(testCase.resultKey)
		ivInBytes := intsToBytes(testCase.resultIV)
		generator := NewPKCS12ParametersGenerator(sha256.New())
		// Convert password to UTF-16BE bytes with null terminator (like Java)
		passwordBytes := StringToUnicodeBytes(testCase.pass)
		generator.Init(passwordBytes, intsToBytes(testCase.salt), testCase.iterations)
		key, iv := generator.GenerateDerivedParameters(32, 16)
		if !reflect.DeepEqual(key, keyInBytes) {
			t.Errorf("key mismatch for password '%s': got %v, want %v", testCase.pass, key, keyInBytes)
		}
		if !reflect.DeepEqual(iv, ivInBytes) {
			t.Errorf("iv mismatch for password '%s': got %v, want %v", testCase.pass, iv, ivInBytes)
		}
	}
}
