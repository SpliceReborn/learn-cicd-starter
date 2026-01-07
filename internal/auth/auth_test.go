package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Define the table
	tests := []struct {
		name          string
		headers       http.Header // Input
		wantKey       string      // Expected API Key
		wantErr       bool        // Do we expect an error?
		expectedError error       // Specific error to check against (optional refinement)
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey 123456"}},
			wantKey: "123456",
			wantErr: false,
		},
		{
			name:          "no auth header included",
			headers:       http.Header{},
			wantKey:       "",
			wantErr:       true,
			expectedError: ErrNoAuthHeaderIncluded, // We can check equality against the var
		},
		{
			name:    "malformed header - wrong prefix",
			headers: http.Header{"Authorization": []string{"Bearer 123456"}},
			wantKey: "",
			wantErr: true,
			// We don't check expectedError here because errors.New() in the function 
			// creates a fresh pointer that won't match a test variable.
		},
		{
			name:    "malformed header - missing key",
			headers: http.Header{"Authorization": []string{"ApiKey"}}, // Too short
			wantKey: "",
			wantErr: true,
		},
	}

	// Iterate over the table
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tc.headers)

			// 1. Check if the error expectation matches
			if (gotErr != nil) != tc.wantErr {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", gotErr, tc.wantErr)
				return
			}

			// 2. If we expected a SPECIFIC error (like the sentinel var), check it
			if tc.expectedError != nil && gotErr != tc.expectedError {
				t.Errorf("GetAPIKey() error = %v, expectedError %v", gotErr, tc.expectedError)
			}

			// 3. Check if the returned key matches
			if gotKey != tc.wantKey {
				t.Errorf("GetAPIKey() = %v, want %v", gotKey, tc.wantKey)
			}
		})
	}
}
