package dub

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func TestUpsert(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPut || request.URL.String() != "https://dub.example/api/links/upsert" {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer secret" {
			t.Fatal("missing bearer token")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"shortLink":"https://go.example/abc"}`))}, nil
	})}
	link, err := Upsert(context.Background(), Config{APIURL: "https://dub.example/api", Token: "secret", Domain: "go.example", URLPrefix: "test:"}, "https://files.example/d?id=abc", "abc", "file.txt", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if link.ShortLink != "https://go.example/abc" {
		t.Fatalf("unexpected short link: %s", link.ShortLink)
	}
}

func TestUpsertRejectsWrongDomain(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"shortLink":"https://evil.example/abc"}`))}, nil
	})}
	_, err := Upsert(context.Background(), Config{APIURL: "https://dub.example/api", Token: "secret", Domain: "go.example"}, "https://files.example/d?id=abc", "abc", "file.txt", 0, true)
	if err == nil {
		t.Fatal("expected domain validation error")
	}
}
