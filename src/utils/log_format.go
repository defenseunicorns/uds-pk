// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

type ShortHandler struct {
	w     io.Writer
	mu    *sync.Mutex
	level slog.Level
	attrs []slog.Attr
}

func NewShortHandler(w io.Writer, level slog.Level) *ShortHandler {
	return &ShortHandler{w: w, mu: &sync.Mutex{}, level: level}
}

func (h *ShortHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *ShortHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandler := *h
	newHandler.attrs = append(newHandler.attrs, attrs...)
	return &newHandler
}

func (h *ShortHandler) WithGroup(name string) slog.Handler {
	// This minimal handler doesn't support groups.
	return h
}

func (h *ShortHandler) Handle(_ context.Context, r slog.Record) error {
	buf := new(bytes.Buffer)

	// Format: [TIME] LEVEL MESSAGE KEY="VALUE"
	fmt.Fprintf(buf, "[%s] %s %s", r.Time.Format(time.RFC3339), r.Level, r.Message)

	// Append attributes from the handler and the log record.
	allAttrs := h.attrs
	r.Attrs(func(a slog.Attr) bool {
		allAttrs = append(allAttrs, a)
		return true
	})

	for _, a := range allAttrs {
		fmt.Fprintf(buf, " %s=%q", a.Key, a.Value.String())
	}

	buf.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf.Bytes())
	return err
}
