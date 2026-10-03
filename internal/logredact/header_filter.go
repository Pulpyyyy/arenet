// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

// Package logredact holds the Caddy log-field filter that masks secrets
// carried in HTTP headers.
//
// Why a module and not configuration. Caddy redacts exactly four headers of
// its own accord — cookie, set-cookie, authorization, proxy-authorization
// (caddy v2.11.4 internal/logmarshalers.go:24-28). Every other header is
// written verbatim, and homelab APIs authenticate with names Caddy has never
// heard of: an operator's access log held a live Dolibarr key under
// `Dolapikey`, beside a `Cookie` that was dutifully REDACTED next to it.
//
// Caddy's own filters cannot express "any header whose name contains key" —
// the filter encoder resolves field paths through an exact map lookup with no
// wildcard (caddy modules/logging/filterencoder.go:466). Enumerating names
// would miss precisely the ones nobody thought of, which is the whole
// problem. But a filter registered on the headers OBJECT is consulted before
// the encoder descends into it (filterencoder.go:267), and whatever Field the
// filter returns is what gets written (:470). So one filter can see the whole
// header table and rewrite it.
package logredact

import (
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ModuleID is the Caddy module ID. It must live under
// caddy.logging.encoders.filter for the filter encoder to load it.
const ModuleID = "caddy.logging.encoders.filter.arenet_header_redact"

// FilterName is what goes in a filter encoder's config: Caddy names a
// filter by the last segment of its ID there ("filter": "regexp"), not by
// the whole thing. Derived from ModuleID so the two cannot drift — getting
// this wrong does not fail validation, it leaves the field unfiltered.
var FilterName = ModuleID[strings.LastIndex(ModuleID, ".")+1:]

// Placeholder replaces a secret's value. Spelled like the one Caddy already
// writes for Cookie, so an operator reading a line recognises it without
// being told.
const Placeholder = "REDACTED"

// SecretHeaderPatterns are the substrings that mark a header as carrying a
// credential. Matched case-insensitively, anywhere in the name.
//
// Substring rather than a list of exact names, because the errors are not
// symmetric: a false positive costs one field of one log line, a false
// negative leaves a live credential on disk through every log rotation. Five
// substrings cover the realistic universe — X-Api-Key, Dolapikey,
// PVEAPIToken, X-Auth-Token, X-N8N-API-KEY, X-Client-Secret, Private-Token,
// X-Vault-Token, X-Hub-Signature.
//
// Deliberately absent, with reasons, because a list nobody can edit has to
// be defensible:
//
//   - "api" alone: Api-Version and Api-Supported-Versions are not secrets,
//     and every real credential spelled with "api" also carries "key" or
//     "token".
//   - "auth": would catch X-authentik-username and friends, which are
//     identities an operator wants to read in their logs, not secrets. The
//     Authorization header itself is already redacted by Caddy.
//   - "session": the first candidate if this list ever grows. Sessions
//     travel in Cookie, which Caddy already covers.
//
// The known false positive, accepted: "monkey" ends with "key", so a header
// named X-Monkey-Business is redacted. No substring rule catches Dolapikey —
// one word, no separator — while sparing monkey. Pinned by
// TestFilter_RedactsFalsePositivesInLongerWords so it is a decision rather
// than a surprise.
//
// There is no operator-facing setting on purpose. Such a list would only be
// edited AFTER someone saw a secret in a log — too late to prevent the thing
// it exists to prevent — and a uniform default means a leak report means the
// same thing on every install. A knob can be added later if a real header
// name defeats these; a shipped knob cannot be taken back.
var SecretHeaderPatterns = []string{
	"key",
	"token",
	"secret",
	"password",
	"credential",
	"signature",
}

func init() {
	caddy.RegisterModule(HeaderFilter{})
}

// HeaderFilter masks the values of headers whose names look like
// credentials. It takes no configuration: see SecretHeaderPatterns.
type HeaderFilter struct{}

// CaddyModule returns the Caddy module information.
func (HeaderFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleID,
		New: func() caddy.Module { return new(HeaderFilter) },
	}
}

// IsSecretHeader reports whether a header name looks like it carries a
// credential. Exported so the emitter's tests and the wiki can be checked
// against the same function the filter uses.
func IsSecretHeader(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range SecretHeaderPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// Filter implements logging.LogFieldFilter.
//
// The field arrives as zap.Any("headers", http.Header-ish object marshaler).
// Anything that is not an object marshaler is passed through untouched: a
// filter that silently dropped a field it did not understand would be worse
// than one that does nothing.
func (f HeaderFilter) Filter(in zapcore.Field) zapcore.Field {
	inner, ok := in.Interface.(zapcore.ObjectMarshaler)
	if !ok {
		return in
	}
	return zap.Object(in.Key, maskingObject{inner: inner})
}

// maskingObject re-marshals the header table through an encoder that
// substitutes the values of secret-looking names.
type maskingObject struct {
	inner zapcore.ObjectMarshaler
}

func (m maskingObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return m.inner.MarshalLogObject(maskingEncoder{ObjectEncoder: enc})
}

// maskingEncoder forwards everything to the real encoder except the values
// of headers whose names look like credentials.
//
// The ObjectEncoder is embedded so the thirty-odd methods of the interface
// keep working untouched and a future zap version that adds one does not
// break the build. Only AddArray and AddString are overridden, which is how
// Caddy writes a header's values (internal/logmarshalers.go:31,
// enc.AddArray(key, LoggableStringArray(val))) — AddString covers the
// single-valued shapes a future Caddy or a different marshaler might use.
//
// The header NAME survives: only its value is replaced. That is the point.
// An operator still learns that a caller presented an API key — useful when
// a backend starts refusing them — without learning the key itself.
// Deleting the field would hide the question along with the answer.
type maskingEncoder struct {
	zapcore.ObjectEncoder
}

func (e maskingEncoder) AddArray(key string, am zapcore.ArrayMarshaler) error {
	if IsSecretHeader(key) {
		return e.ObjectEncoder.AddArray(key, redactedValues{})
	}
	return e.ObjectEncoder.AddArray(key, am)
}

func (e maskingEncoder) AddString(key, value string) {
	if IsSecretHeader(key) {
		e.ObjectEncoder.AddString(key, Placeholder)
		return
	}
	e.ObjectEncoder.AddString(key, value)
}

// redactedValues renders as a single-element array holding the placeholder,
// matching the shape of a header's value list so a log consumer that expects
// an array still parses the line.
type redactedValues struct{}

func (redactedValues) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	enc.AppendString(Placeholder)
	return nil
}

// Interface guards.
//
// logging.LogFieldFilter is the one that matters: the filter encoder loads
// this module and asserts to that interface at provision time, so a
// signature drift would otherwise surface as a runtime failure on a live
// config reload rather than here.
var (
	_ caddy.Module            = (*HeaderFilter)(nil)
	_ logging.LogFieldFilter  = HeaderFilter{}
	_ zapcore.ObjectMarshaler = maskingObject{}
	_ zapcore.ArrayMarshaler  = redactedValues{}
)
