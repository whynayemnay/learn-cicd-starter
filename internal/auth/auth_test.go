package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantKey     string
		wantErr     error
	}{
		{
			name:        "missing header",
			headerValue: "",
			wantKey:     "",
			wantErr:     ErrNoAuthHeaderIncluded,
		},
		{
			name:        "valid header",
			headerValue: "ApiKey my-secret",
			wantKey:     "my-secret",
			wantErr:     nil,
		},
		{
			name:        "no space between scheme and key",
			headerValue: "ApiKeymy-secret",
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
		},
		{
			name:        "wrong scheme",
			headerValue: "Bearer my-secret",
			wantKey:     "",
			wantErr:     errors.New("malformed authorization header"),
		},
		{
			name:        "multiple spaces between scheme and key (returns empty second element)",
			headerValue: "ApiKey    my-secret",
			wantKey:     "", // current implementation returns splitAuth[1] which will be empty
			wantErr:     nil,
		},
		{
			name:        "trailing space after key",
			headerValue: "ApiKey my-secret ",
			wantKey:     "my-secret",
			wantErr:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.headerValue != "" {
				h.Set("Authorization", tc.headerValue)
			}

			gotKey, err := GetAPIKey(h)

			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				if gotKey != tc.wantKey {
					t.Fatalf("expected key %q, got %q", tc.wantKey, gotKey)
				}
			} else {
				// special-case ErrNoAuthHeaderIncluded sentinel comparison
				if errors.Is(tc.wantErr, ErrNoAuthHeaderIncluded) {
					if !errors.Is(err, ErrNoAuthHeaderIncluded) {
						t.Fatalf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
					}
					return
				}
				// otherwise compare error message
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr.Error() {
					t.Fatalf("expected error message %q, got %q", tc.wantErr.Error(), err.Error())
				}
			}
		})
	}
}
