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

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/automation"
	"github.com/barto95100/arenet/internal/storage"
)

// SnapshotExtras (v2.29) carries the config areas the first backup
// format left out. A snapshot without it (backup ≤ v2.25) restores
// without touching any of these buckets; a snapshot with it replaces
// every one of them. Runtime state (last_* fields, token last use,
// auto-detected server position) is never exported.
type SnapshotExtras struct {
	ManagedDomains  []storage.ManagedDomain        `json:"managed_domains"`
	ErrorTemplates  []storage.ErrorPageTemplate    `json:"error_templates"`
	MaintenancePage *storage.MaintenancePageConfig `json:"maintenance_page,omitempty"`
	// AlertChannels' config secrets (SMTP password, webhook URL and
	// header values) are redacted in a no-secrets export.
	AlertChannels []storage.Channel   `json:"alert_channels"`
	AlertRules    []storage.AlertRule `json:"alert_rules"`
	// CrowdSecConfig.APIKey and WatcherCredentials.Password are secrets.
	CrowdSecConfig     *storage.CrowdSecConfig     `json:"crowdsec_config,omitempty"`
	WatcherCredentials *storage.WatcherCredentials `json:"crowdsec_watcher,omitempty"`
	AutomationRules    json.RawMessage             `json:"automation_rules,omitempty"`
	UpdateCheck        *storage.UpdateCheckConfig  `json:"update_check,omitempty"`
	GeoIPUpdate        *storage.GeoIPUpdateConfig  `json:"geoip_update,omitempty"`
	// ServerPosition is exported only when set manually.
	ServerPosition *storage.ServerPositionRecord `json:"server_position,omitempty"`
	// BackupSchedule (v2.33) is the scheduled-backup config; its
	// passphrase is a secret. Runtime status is never exported.
	BackupSchedule *storage.BackupScheduleConfig `json:"backup_schedule,omitempty"`
	// RouteCheck (v2.35) is the post-apply route check toggle.
	RouteCheck *storage.RouteCheckConfig `json:"route_check,omitempty"`
	// TCPServices (v2.42) are the layer-4 relays. No secret is
	// involved: a relay carries addresses and gates, nothing else.
	TCPServices []storage.TCPService `json:"tcp_services"`
	// APITokens are the service-account tokens; token_hash is a secret.
	APITokens []auth.APIToken `json:"api_tokens"`
}

// Entity names of the extras, used in sentinel identities and
// IncompleteRows.
const (
	entityAlertChannels  = "alert_channels"
	entityCrowdSec       = "crowdsec_config"
	entityWatcher        = "crowdsec_watcher"
	entityAPITokens      = "api_tokens"
	entityBackupSchedule = "backup_schedule"
	singletonIdentity    = "default"
	serverPositionManual = "manual"
	// placeholderWebhookURL stands in for a cleared webhook URL during
	// validation only (AllowIncompleteRestore dérogation).
	placeholderWebhookURL = "https://redacted.invalid/"
	// placeholderSecret stands in for a cleared secret during
	// validation only.
	placeholderSecret = "cleared-by-incomplete-restore"
)

// Channel config secret keys (camelCase, internal/alerting/config.go).
const (
	cfgKeySMTPPassword = "smtpPassword"
	cfgKeyURL          = "url"
	cfgKeyHeaders      = "headers"
)

// exportExtras reads every extras area from the live store.
func exportExtras(ctx context.Context, store Storer) (*SnapshotExtras, error) {
	ex := &SnapshotExtras{}
	var err error
	if ex.ManagedDomains, err = store.ListManagedDomains(ctx); err != nil {
		return nil, fmt.Errorf("export: list managed domains: %w", err)
	}
	if ex.ErrorTemplates, err = store.ListErrorPageTemplates(ctx); err != nil {
		return nil, fmt.Errorf("export: list error templates: %w", err)
	}
	if ex.TCPServices, err = store.ListTCPServices(ctx); err != nil {
		return nil, fmt.Errorf("export: list tcp services: %w", err)
	}
	mp, err := store.GetMaintenancePageConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: get maintenance page: %w", err)
	}
	ex.MaintenancePage = &mp

	channels, err := store.ListAlertChannels(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: list alert channels: %w", err)
	}
	for i := range channels {
		channels[i].LastSentAt, channels[i].LastError, channels[i].LastErrorAt = nil, "", nil
	}
	ex.AlertChannels = channels
	rules, err := store.ListAlertRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: list alert rules: %w", err)
	}
	for i := range rules {
		r := &rules[i]
		r.LastFiredAt, r.LastEvalAt, r.LastError, r.LastErrorAt, r.LastMatched = nil, nil, "", nil, false
	}
	ex.AlertRules = rules

	if cs, err := store.GetCrowdSecConfig(ctx); err == nil {
		ex.CrowdSecConfig = &cs
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("export: get crowdsec config: %w", err)
	}
	if wc, err := store.GetWatcherCredentials(ctx); err == nil {
		ex.WatcherCredentials = &wc
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("export: get watcher credentials: %w", err)
	}
	if raw, err := store.GetAutomationRulesRaw(ctx); err == nil {
		ex.AutomationRules = raw
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("export: get automation rules: %w", err)
	}
	uc, err := store.GetUpdateCheckConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: get update check config: %w", err)
	}
	ex.UpdateCheck = &uc
	gu, err := store.GetGeoIPUpdateConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: get geoip update config: %w", err)
	}
	ex.GeoIPUpdate = &gu
	if sp, err := store.GetServerPosition(ctx); err == nil {
		if sp.Mode == serverPositionManual {
			ex.ServerPosition = &sp
		}
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("export: get server position: %w", err)
	}
	bs, err := store.GetBackupSchedule(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: get backup schedule: %w", err)
	}
	ex.BackupSchedule = &bs
	rc, err := store.GetRouteCheckConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: get route check config: %w", err)
	}
	ex.RouteCheck = &rc

	tokens, err := listAPITokens(ctx, store)
	if err != nil {
		return nil, err
	}
	for i := range tokens {
		tokens[i].LastUsedAt = nil
	}
	ex.APITokens = tokens
	return ex, nil
}

// listAPITokens decodes the raw api_tokens rows, sorted by creation.
// A corrupted row is an error: silently dropping a token would make
// the backup lie about what it holds.
func listAPITokens(ctx context.Context, store Storer) ([]auth.APIToken, error) {
	rows, err := store.ListAPITokenRows(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: list api tokens: %w", err)
	}
	out := make([]auth.APIToken, 0, len(rows))
	for id, raw := range rows {
		var t auth.APIToken
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("export: decode api token %q: %w", id, err)
		}
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b auth.APIToken) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return bytes.Compare([]byte(a.ID), []byte(b.ID))
	})
	return out, nil
}

// decodeConfig decodes a channel config into a generic map, keeping
// numbers verbatim. A config that is not a JSON object yields nil.
func decodeConfig(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil
	}
	return m
}

// liveExtras is the live state the extras sentinels inherit from.
type liveExtras struct {
	channelsByID map[string]storage.Channel
	crowdSec     *storage.CrowdSecConfig
	watcher      *storage.WatcherCredentials
	tokensByID   map[string]auth.APIToken
	backupPass   string
}

func readLiveExtras(ctx context.Context, store Storer) (*liveExtras, error) {
	le := &liveExtras{channelsByID: map[string]storage.Channel{}, tokensByID: map[string]auth.APIToken{}}
	channels, err := store.ListAlertChannels(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range channels {
		le.channelsByID[c.ID] = c
	}
	if cs, err := store.GetCrowdSecConfig(ctx); err == nil {
		le.crowdSec = &cs
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	if wc, err := store.GetWatcherCredentials(ctx); err == nil {
		le.watcher = &wc
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	tokens, err := listAPITokens(ctx, store)
	if err != nil {
		return nil, err
	}
	for _, t := range tokens {
		le.tokensByID[t.ID] = t
	}
	bs, err := store.GetBackupSchedule(ctx)
	if err != nil {
		return nil, err
	}
	le.backupPass = bs.Passphrase
	return le, nil
}

// resolveFunc is resolveSentinels' per-field resolver.
type resolveFunc func(entity, identity, field, current string, lookup func() (string, bool)) (string, error)

// resolveExtras returns a copy of ex with every sentinel inherited or
// cleared. A token whose hash is cleared is dropped: a token without
// a hash can never authenticate.
func resolveExtras(ex *SnapshotExtras, live *liveExtras, resolve resolveFunc) (*SnapshotExtras, error) {
	out := *ex
	out.AlertChannels = slices.Clone(ex.AlertChannels)
	for i := range out.AlertChannels {
		c := &out.AlertChannels[i]
		liveCh, ok := live.channelsByID[c.ID]
		var liveCfg map[string]any
		if ok && liveCh.Kind == c.Kind {
			liveCfg = decodeConfig(liveCh.Config)
		}
		cfg, err := resolveChannelConfig(c, liveCfg, resolve)
		if err != nil {
			return nil, err
		}
		c.Config = cfg
	}

	if ex.CrowdSecConfig != nil {
		cp := *ex.CrowdSecConfig
		v, err := resolve(entityCrowdSec, singletonIdentity, "api_key", cp.APIKey, func() (string, bool) {
			if live.crowdSec != nil {
				return live.crowdSec.APIKey, true
			}
			return "", false
		})
		if err != nil {
			return nil, err
		}
		cp.APIKey = v
		out.CrowdSecConfig = &cp
	}
	if ex.WatcherCredentials != nil {
		cp := *ex.WatcherCredentials
		v, err := resolve(entityWatcher, singletonIdentity, "password", cp.Password, func() (string, bool) {
			if live.watcher != nil {
				return live.watcher.Password, true
			}
			return "", false
		})
		if err != nil {
			return nil, err
		}
		cp.Password = v
		out.WatcherCredentials = &cp
	}
	if ex.BackupSchedule != nil {
		cp := *ex.BackupSchedule
		v, err := resolve(entityBackupSchedule, singletonIdentity, "passphrase", cp.Passphrase, func() (string, bool) {
			return live.backupPass, live.backupPass != ""
		})
		if err != nil {
			return nil, err
		}
		cp.Passphrase = v
		out.BackupSchedule = &cp
	}

	out.APITokens = make([]auth.APIToken, 0, len(ex.APITokens))
	for _, t := range ex.APITokens {
		v, err := resolve(entityAPITokens, t.ID, "token_hash", t.TokenHash, func() (string, bool) {
			if lt, ok := live.tokensByID[t.ID]; ok {
				return lt.TokenHash, true
			}
			return "", false
		})
		if err != nil {
			return nil, err
		}
		if v == "" {
			continue
		}
		t.TokenHash = v
		out.APITokens = append(out.APITokens, t)
	}
	return &out, nil
}

// resolveChannelConfig resolves the sentinels of one channel config
// against the live config of the same id and kind (liveCfg, nil when
// none). The config is re-encoded only when a sentinel was present.
func resolveChannelConfig(c *storage.Channel, liveCfg map[string]any, resolve resolveFunc) (json.RawMessage, error) {
	if !bytes.Contains(c.Config, []byte(SentinelLiteral)) {
		return c.Config, nil
	}
	m := decodeConfig(c.Config)
	if m == nil {
		// Whole config redacted (it was undecodable at export):
		// inherit the live config as a unit.
		v, err := resolve(entityAlertChannels, c.ID, "config", SentinelLiteral, func() (string, bool) {
			if liveCfg == nil {
				return "", false
			}
			b, err := json.Marshal(liveCfg)
			return string(b), err == nil
		})
		if err != nil {
			return nil, err
		}
		if v == "" {
			return json.RawMessage("{}"), nil
		}
		return json.RawMessage(v), nil
	}
	field := func(key string) error {
		cur, ok := m[key].(string)
		if !ok {
			return nil
		}
		v, err := resolve(entityAlertChannels, c.ID, "config."+key, cur, func() (string, bool) {
			s, ok := liveCfg[key].(string)
			return s, ok
		})
		if err != nil {
			return err
		}
		m[key] = v
		return nil
	}
	if err := field(cfgKeySMTPPassword); err != nil {
		return nil, err
	}
	if err := field(cfgKeyURL); err != nil {
		return nil, err
	}
	if h, ok := m[cfgKeyHeaders].(map[string]any); ok {
		liveH, _ := liveCfg[cfgKeyHeaders].(map[string]any)
		for k, cur := range h {
			s, ok := cur.(string)
			if !ok {
				continue
			}
			v, err := resolve(entityAlertChannels, c.ID, "config."+cfgKeyHeaders+"["+k+"]", s, func() (string, bool) {
				lv, ok := liveH[k].(string)
				return lv, ok
			})
			if err != nil {
				return nil, err
			}
			h[k] = v
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("restore: alert channel %q: encode config: %w", c.ID, err)
	}
	return b, nil
}

// validateExtras re-checks the extras invariants against the
// snapshot's own sets (the live state is about to be replaced).
func validateExtras(snap *Snapshot, cleared clearedSet) error {
	ex := snap.Extras
	if ex == nil {
		return nil
	}
	dnsIDs := map[string]bool{}
	for _, d := range snap.DNSProviders {
		dnsIDs[d.ID] = true
	}
	seenApex := map[string]bool{}
	for _, md := range ex.ManagedDomains {
		if err := storage.ValidateManagedDomain(md); err != nil {
			return fmt.Errorf("restore: managed domain %q: %w", md.Apex, err)
		}
		if seenApex[md.Apex] {
			return fmt.Errorf("restore: managed domain %q appears twice", md.Apex)
		}
		seenApex[md.Apex] = true
		if md.ProviderID != "" && !dnsIDs[md.ProviderID] {
			return fmt.Errorf("restore: managed domain %q references DNS provider %q which is not in the snapshot", md.Apex, md.ProviderID)
		}
	}

	catchall := 0

	routeDefault := 0
	seenTmpl := map[string]bool{}
	for _, t := range ex.ErrorTemplates {
		if err := storage.ValidateErrorPageTemplate(t); err != nil {
			return fmt.Errorf("restore: error template %q: %w", t.ID, err)
		}
		if seenTmpl[t.ID] {
			return fmt.Errorf("restore: error template %q appears twice", t.ID)
		}
		seenTmpl[t.ID] = true
		if t.IsCatchallDefault {
			catchall++
		}
		if t.IsRouteDefault {
			routeDefault++
		}
	}
	if catchall > 1 {
		return fmt.Errorf("restore: %d error templates are marked catch-all default; at most one is allowed", catchall)
	}
	// v2.51 — same invariant for the route default, and for a sharper
	// reason: resolveErrorPage walks the template map, whose iteration
	// order is random, so two flagged templates would serve different
	// error pages from one reload to the next.
	if routeDefault > 1 {
		return fmt.Errorf("restore: %d error templates are marked route default; at most one is allowed", routeDefault)
	}

	channelIDs := map[string]bool{}
	for _, c := range ex.AlertChannels {
		if err := validateChannelWithDerogation(c, cleared); err != nil {
			return err
		}
		if channelIDs[c.ID] {
			return fmt.Errorf("restore: alert channel %q appears twice", c.ID)
		}
		channelIDs[c.ID] = true
	}
	for _, r := range ex.AlertRules {
		if err := storage.ValidateAlertRule(r); err != nil {
			return fmt.Errorf("restore: alert rule %q: %w", r.ID, err)
		}
		for _, ch := range r.Channels {
			if !channelIDs[ch] {
				return fmt.Errorf("restore: alert rule %q references channel %q which is not in the snapshot", r.Name, ch)
			}
		}
	}

	if ex.CrowdSecConfig != nil {
		if err := storage.ValidateCrowdSecConfig(*ex.CrowdSecConfig); err != nil {
			return fmt.Errorf("restore: crowdsec config: %w", err)
		}
	}
	if ex.WatcherCredentials != nil {
		wc := *ex.WatcherCredentials
		if wc.Password == "" && cleared.has(entityWatcher, singletonIdentity, "password") {
			wc.Password = placeholderSecret
		}
		if err := storage.ValidateWatcherCredentials(wc); err != nil {
			return fmt.Errorf("restore: crowdsec watcher: %w", err)
		}
	}
	if bs := ex.BackupSchedule; bs != nil {
		if err := validateBackupSchedule(*bs, ex.AlertChannels, cleared); err != nil {
			return err
		}
	}
	if len(ex.AutomationRules) > 0 {
		// Stored as the {"rules": RuleSet} envelope the automation
		// API writes (internal/api/automation_handlers.go putRules).
		var envelope struct {
			Rules automation.RuleSet `json:"rules"`
		}
		if err := json.Unmarshal(ex.AutomationRules, &envelope); err != nil {
			return fmt.Errorf("restore: automation rules: %w", err)
		}
		if err := envelope.Rules.Validate(); err != nil {
			return fmt.Errorf("restore: automation rules: %w", err)
		}
	}

	return validateTokens(ex.APITokens, snap.Users)
}

// validateChannelWithDerogation validates a channel and its per-kind
// config, substituting a placeholder for a URL the restore cleared.
func validateChannelWithDerogation(c storage.Channel, cleared clearedSet) error {
	if err := storage.ValidateAlertChannel(c); err != nil {
		return fmt.Errorf("restore: alert channel %q: %w", c.Name, err)
	}
	cfg := c.Config
	if cleared.has(entityAlertChannels, c.ID, "config") {
		return nil
	}
	if cleared.has(entityAlertChannels, c.ID, "config."+cfgKeyURL) {
		if m := decodeConfig(cfg); m != nil {
			m[cfgKeyURL] = placeholderWebhookURL
			if b, err := json.Marshal(m); err == nil {
				cfg = b
			}
		}
	}
	var err error
	switch c.Kind {
	case storage.ChannelKindWebhook:
		_, err = alerting.ParseWebhookConfig(cfg)
	case storage.ChannelKindEmail:
		_, err = alerting.ParseEmailConfig(cfg)
	}
	if err != nil {
		return fmt.Errorf("restore: alert channel %q: %w", c.Name, err)
	}
	return nil
}

// validateTokens checks each token belongs to a service account of
// the snapshot and that no account holds two active tokens.
func validateTokens(tokens []auth.APIToken, users []auth.User) error {
	service := map[string]bool{}
	for _, u := range users {
		if u.AuthSource == auth.UserAuthSourceService {
			service[u.ID] = true
		}
	}
	now := time.Now()
	active := map[string]string{}
	seen := map[string]bool{}
	for _, t := range tokens {
		if t.ID == "" || t.TokenHash == "" {
			return fmt.Errorf("restore: api token %q: id and token_hash must not be empty", t.ID)
		}
		if seen[t.ID] {
			return fmt.Errorf("restore: api token %q appears twice", t.ID)
		}
		seen[t.ID] = true
		if !service[t.UserID] {
			return fmt.Errorf("restore: api token %q (%s) belongs to user %q which is not a service account of the snapshot", t.ID, t.Name, t.UserID)
		}
		if t.IsActive(now) {
			if other, dup := active[t.UserID]; dup {
				return fmt.Errorf("restore: service account %q has two active tokens (%s, %s)", t.UserID, other, t.ID)
			}
			active[t.UserID] = t.ID
		}
	}
	return nil
}

// extrasRestoreInput converts resolved extras into the storage input.
func extrasRestoreInput(ex *SnapshotExtras) (*storage.RestoreExtras, error) {
	if ex == nil {
		return nil, nil
	}
	tokens := make(map[string][]byte, len(ex.APITokens))
	for _, t := range ex.APITokens {
		b, err := json.Marshal(t)
		if err != nil {
			return nil, fmt.Errorf("marshal api token %q: %w", t.ID, err)
		}
		tokens[t.ID] = b
	}
	return &storage.RestoreExtras{
		ManagedDomains:     ex.ManagedDomains,
		ErrorTemplates:     ex.ErrorTemplates,
		TCPServices:        ex.TCPServices,
		MaintenancePage:    ex.MaintenancePage,
		AlertChannels:      ex.AlertChannels,
		AlertRules:         ex.AlertRules,
		CrowdSecConfig:     ex.CrowdSecConfig,
		WatcherCredentials: ex.WatcherCredentials,
		AutomationRules:    ex.AutomationRules,
		UpdateCheck:        ex.UpdateCheck,
		GeoIPUpdate:        ex.GeoIPUpdate,
		ServerPosition:     ex.ServerPosition,
		BackupSchedule:     ex.BackupSchedule,
		RouteCheck:         ex.RouteCheck,
		APITokens:          tokens,
	}, nil
}

// validateBackupSchedule checks a restored schedule: shape, a
// passphrase when enabled (unless the restore cleared it), and
// channels that exist in the snapshot (the email one of kind email).
func validateBackupSchedule(bs storage.BackupScheduleConfig, channels []storage.Channel, cleared clearedSet) error {
	if err := storage.ValidateBackupSchedule(bs); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if bs.Enabled && bs.Passphrase == "" && !cleared.has(entityBackupSchedule, singletonIdentity, "passphrase") {
		return errors.New("restore: backup_schedule is enabled without a passphrase")
	}
	kinds := make(map[string]string, len(channels))
	for _, c := range channels {
		kinds[c.ID] = c.Kind
	}
	if bs.EmailMode != storage.BackupEmailNever && kinds[bs.EmailChannelID] != storage.ChannelKindEmail {
		return fmt.Errorf("restore: backup_schedule email channel %q is not an email channel of the snapshot", bs.EmailChannelID)
	}
	for _, id := range bs.AlertChannelIDs {
		if _, ok := kinds[id]; !ok {
			return fmt.Errorf("restore: backup_schedule alert channel %q is not in the snapshot", id)
		}
	}
	return nil
}
