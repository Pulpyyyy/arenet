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

package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AL.1.b — WebhookSender. HTTP POST of the AlertEvent
// payload to an operator-configured URL. V1 = one
// attempt, no retry (per D1 ADR). Failure modes:
//   - network error → wrapped + returned
//   - non-2xx response → ErrTransport with status code
//   - context cancelled → context.DeadlineExceeded
//     surfaces (the dispatcher uses errors.Is for
//     classification)
//
// The sender holds the typed config + an http.Client.
// One sender per Channel; the dispatcher constructs them
// on the hot path from the stored config.

// WebhookSender ships AlertEvent via HTTP POST.
type WebhookSender struct {
	cfg    WebhookConfig
	client *http.Client
}

// NewWebhookSender constructs a sender from a typed
// config. The config must have already passed
// WebhookConfig.Validate (the API CRUD layer is the
// guard). Timeout is read from cfg.TimeoutSeconds at
// construction; subsequent dispatches honour it via the
// http.Client.Timeout field.
func NewWebhookSender(cfg WebhookConfig) *WebhookSender {
	cfg = cfg.WithDefaults()
	return &WebhookSender{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		},
	}
}

// Kind implements AlertSender.
func (s *WebhookSender) Kind() string { return "webhook" }

// Send implements AlertSender. One attempt, no retry per
// AL.1.b D1.
func (s *WebhookSender) Send(ctx context.Context, evt AlertEvent) error {
	body, err := s.buildBody(evt)
	if err != nil {
		return fmt.Errorf("webhook: build body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, s.cfg.Method, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	// Default Content-Type. Operator headers can override.
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "arenet/alerting-webhook")
	for k, v := range s.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: send: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: upstream returned HTTP %d: %s",
			resp.StatusCode, readErrorSnippet(resp.Body))
	}
	return nil
}

// errorSnippetLimit bounds how much of a refusal we quote. Enough for a
// provider's explanation, short enough for a log line and for the error
// the UI shows.
const errorSnippetLimit = 400

// readErrorSnippet quotes the start of a failed response body.
//
// v2.53 — it used to be discarded. An operator pointed a webhook channel
// at a Discord URL and got `upstream returned HTTP 400` with nothing
// else, while Discord's own body said exactly what was wrong. The cause
// was one field name, and the answer was already in the response we threw
// away.
//
// Whitespace is collapsed so a multi-line JSON error stays one log line.
// A body that reads empty says so rather than producing a dangling colon.
func readErrorSnippet(body io.Reader) string {
	raw, err := io.ReadAll(io.LimitReader(body, errorSnippetLimit))
	if err != nil || len(raw) == 0 {
		return "(no response body)"
	}
	return strings.Join(strings.Fields(string(raw)), " ")
}

// buildBody renders the request body. When BodyTemplate
// is empty the default is the JSON-marshalled
// AlertEvent — most webhook receivers (alertmanager,
// generic JSON handlers) consume that shape directly.
// When BodyTemplate is set, the rendered string is the
// body verbatim — operators templating into Slack-shape
// JSON or a custom plain-text format own the formatting.
func (s *WebhookSender) buildBody(evt AlertEvent) ([]byte, error) {
	if s.cfg.BodyTemplate == "" {
		return json.Marshal(evt)
	}
	t, err := compileBodyTemplate(s.cfg.BodyTemplate)
	if err != nil {
		// Should never happen — Validate at CRUD time
		// already compiled the template. Defensive
		// fallback so a broken template at send time
		// doesn't crash the dispatcher.
		return nil, fmt.Errorf("compile template: %w", err)
	}
	rendered, err := renderTemplate(t, evt)
	if err != nil {
		return nil, fmt.Errorf("render template: %w", err)
	}
	return []byte(rendered), nil
}
