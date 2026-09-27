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

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
)

const (
	bucketAccessLog = "access_log"
	accessLogKey    = "config"
)

// Access-log rotation bounds. The point of a ceiling is that a homelab
// SSD does not fill up, so these are deliberately far below Caddy's own
// defaults of 100 MB x 10 files (~1 GB,
// caddy modules/logging/filewriter.go:251-262).
const (
	AccessLogDefaultRollSizeMB = 10
	AccessLogDefaultRollKeep   = 5
	AccessLogMaxRollSizeMB     = 1024
	AccessLogMaxRollKeep       = 100
)

// AccessLogConfig turns on the HTTP access log (v2.50) and bounds it.
//
// It exists for one reason: CrowdSec cannot detect anything about this
// host without a request log to parse. Arenet emitted none, so an agent
// installed beside it enforced the community blocklist and detected
// nothing — with nothing saying so.
//
// Disabled by default, and that is a decision rather than caution: the
// file records every visitor's IP and every URL they asked for. Whether
// to write that down is the operator's call.
type AccessLogConfig struct {
	Enabled bool `json:"enabled"`

	// Path is where to write. Empty means the configured default, which
	// differs per install: /var/log/arenet/access.log under systemd (the
	// unit's LogsDirectory= provides it), and <data-dir>/logs/access.log
	// otherwise — in a container /var/log is the writable layer, so a
	// log there dies with the container.
	//
	// Resolution lives in the config layer, not here: the API resolves
	// it before answering so the UI can print the real path.
	Path string `json:"path,omitempty"`

	// RollSizeMB is the size at which a file is rotated, RollKeep how
	// many rotated files are kept. Worst case on disk is roughly
	// RollSizeMB * (RollKeep + 1), less whatever gzip saves.
	RollSizeMB int `json:"rollSizeMB"`
	RollKeep   int `json:"rollKeep"`

	// Compress gzips rotated files. On by default: request logs are
	// extremely compressible, and the ceiling is the whole point.
	Compress bool `json:"compress"`
}

// DefaultAccessLogConfig is what a fresh install has: off, with bounds
// already sane so enabling it is one click and never a disk incident.
func DefaultAccessLogConfig() AccessLogConfig {
	return AccessLogConfig{
		Enabled:    false,
		RollSizeMB: AccessLogDefaultRollSizeMB,
		RollKeep:   AccessLogDefaultRollKeep,
		Compress:   true,
	}
}

// Validate normalises the config and refuses what would be unbounded or
// unwritable.
func (c *AccessLogConfig) Validate() error {
	c.Path = strings.TrimSpace(c.Path)
	if c.Path != "" {
		if !filepath.IsAbs(c.Path) {
			// A relative path would resolve against Caddy's working
			// directory, which is not the operator's shell and not
			// documented anywhere. Refusing is kinder than writing the
			// file somewhere nobody looks.
			return fmt.Errorf("access log: path %q must be absolute", c.Path)
		}
		if strings.HasSuffix(c.Path, string(filepath.Separator)) {
			return fmt.Errorf("access log: path %q must be a file, not a directory", c.Path)
		}
	}

	// Zero means "unset" rather than "unlimited": Caddy would substitute
	// its own 100 MB / 10 files, which is the ceiling this feature
	// exists to avoid.
	if c.RollSizeMB == 0 {
		c.RollSizeMB = AccessLogDefaultRollSizeMB
	}
	if c.RollKeep == 0 {
		c.RollKeep = AccessLogDefaultRollKeep
	}
	if c.RollSizeMB < 1 || c.RollSizeMB > AccessLogMaxRollSizeMB {
		return fmt.Errorf("access log: rollSizeMB %d out of range 1-%d",
			c.RollSizeMB, AccessLogMaxRollSizeMB)
	}
	if c.RollKeep < 1 || c.RollKeep > AccessLogMaxRollKeep {
		return fmt.Errorf("access log: rollKeep %d out of range 1-%d",
			c.RollKeep, AccessLogMaxRollKeep)
	}
	return nil
}

// CeilingMB is the worst case this config can occupy on disk, before
// compression. Surfaced because it is the number an operator actually
// wants — "10 MB, 5 files" answers a question nobody asked.
func (c AccessLogConfig) CeilingMB() int {
	return c.RollSizeMB * (c.RollKeep + 1)
}

// GetAccessLogConfig returns the config; a fresh install (no row) is
// disabled with default bounds.
func (s *Store) GetAccessLogConfig(ctx context.Context) (AccessLogConfig, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	out := DefaultAccessLogConfig()
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketAccessLog)).Get([]byte(accessLogKey))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return AccessLogConfig{}, err
	}
	return out, nil
}

// PutAccessLogConfig validates then stores the config.
func (s *Store) PutAccessLogConfig(ctx context.Context, c AccessLogConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal access log config: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketAccessLog)).Put([]byte(accessLogKey), buf)
	})
}
