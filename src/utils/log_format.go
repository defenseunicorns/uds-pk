// Copyright 2024 Defense Unicorns
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Defense-Unicorns-Commercial

package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

type ShortHandler struct {
	w      io.Writer
	mu     *sync.Mutex
	level  slog.Level
	attrs  []slog.Attr
	colors bool
}

// ANSI color codes
const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorReset  = "\033[0m"
)

// A map to associate log levels with colors.
var levelColors = map[slog.Level]string{
	slog.LevelDebug: colorBlue,
	slog.LevelInfo:  colorGreen,
	slog.LevelWarn:  colorYellow,
	slog.LevelError: colorRed,
}

func PrettyLogHandler(w io.Writer, level slog.Level) *ShortHandler {
	h := &ShortHandler{
		w:     w,
		mu:    &sync.Mutex{},
		level: level,
	}

	if f, ok := w.(*os.File); ok {
		stat, _ := f.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			h.colors = true
		}
	}

	return h
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
	fmt.Fprintf(buf, "[%s] ", r.Time.Format(time.RFC3339))

	// Write level with color if enabled.
	levelStr := r.Level.String()
	if h.colors {
		if color, ok := levelColors[r.Level]; ok {
			fmt.Fprintf(buf, "%s%s%s", color, levelStr, colorReset)
		} else {
			buf.WriteString(levelStr)
		}
	} else {
		buf.WriteString(levelStr)
	}

	fmt.Fprintf(buf, " %s", r.Message)

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
