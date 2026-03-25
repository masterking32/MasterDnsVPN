// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package logger

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		raw  string
		want int
	}{
		{raw: "debug", want: levelDebug},
		{raw: "INFO", want: levelInfo},
		{raw: "warn", want: levelWarn},
		{raw: "warning", want: levelWarn},
		{raw: "critical", want: levelError},
		{raw: "error", want: levelError},
		{raw: "unknown", want: levelInfo},
	}

	for _, tt := range tests {
		if got := parseLevel(tt.raw); got != tt.want {
			t.Fatalf("parseLevel(%q) = %d, want %d", tt.raw, got, tt.want)
		}
	}
}

func TestRenderColorTags(t *testing.T) {
	got := renderColorTags("<green>ok</green> <cyan>test</cyan> <unknown>x</unknown>")
	if !strings.Contains(got, "\x1b[32m") {
		t.Fatal("expected green ANSI code in rendered string")
	}
	if !strings.Contains(got, "\x1b[36m") {
		t.Fatal("expected cyan ANSI code in rendered string")
	}
	if !strings.Contains(got, "<unknown>x</unknown>") {
		t.Fatal("unknown tags should be preserved")
	}
}

func TestRenderColorTagsRestoresParentColor(t *testing.T) {
	got := renderColorTags("<green>Listener <cyan>127.0.0.1:5350</cyan> Ready</green>")
	want := "\x1b[32mListener \x1b[36m127.0.0.1:5350\x1b[0m\x1b[32m Ready\x1b[0m"
	if got != want {
		t.Fatalf("renderColorTags() = %q, want %q", got, want)
	}
}

func TestLoggerSuppressesBelowLevel(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{
		name:          "test",
		level:         levelWarn,
		consoleWriter: &buf,
		color:         false,
		appNameText:   "[test]",
	}

	l.Infof("info message")
	l.Warnf("warn message")

	output := buf.String()
	if strings.Contains(output, "info message") {
		t.Fatal("info message should be suppressed at WARN level")
	}
	if !strings.Contains(output, "warn message") {
		t.Fatal("warn message should be logged at WARN level")
	}
}

func TestShouldUseColorHonorsNoColor(t *testing.T) {
	oldNoColor := os.Getenv("NO_COLOR")
	oldForceColor := os.Getenv("FORCE_COLOR")
	t.Cleanup(func() {
		_ = os.Setenv("NO_COLOR", oldNoColor)
		_ = os.Setenv("FORCE_COLOR", oldForceColor)
	})

	_ = os.Setenv("FORCE_COLOR", "1")
	_ = os.Setenv("NO_COLOR", "1")

	if shouldUseColor() {
		t.Fatal("NO_COLOR should disable colors even when FORCE_COLOR is set")
	}
}

func TestSubLoggerPrefix(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{
		name:          "test",
		level:         levelDebug,
		consoleWriter: &buf,
		color:         false,
		appNameText:   "[test]",
	}

	sub := l.With("Sess", "3")
	sub.Infof("hello %s", "world")

	output := buf.String()
	if !strings.Contains(output, "[Sess:3] hello world") {
		t.Fatalf("expected prefix in output, got: %s", output)
	}
}

func TestSubLoggerChaining(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{
		name:          "test",
		level:         levelDebug,
		consoleWriter: &buf,
		color:         false,
		appNameText:   "[test]",
	}

	sub := l.With("Sess", "3").With("Str", "42")
	sub.Debugf("stream opened")

	output := buf.String()
	if !strings.Contains(output, "[Sess:3] [Str:42] stream opened") {
		t.Fatalf("expected chained prefix in output, got: %s", output)
	}
}

func TestSubLoggerRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{
		name:          "test",
		level:         levelWarn,
		consoleWriter: &buf,
		color:         false,
		appNameText:   "[test]",
	}

	sub := l.With("Sess", "1")
	sub.Debugf("should not appear")
	sub.Infof("should not appear")
	sub.Warnf("should appear")

	output := buf.String()
	if strings.Contains(output, "should not appear") {
		t.Fatal("sub-logger should suppress below parent level")
	}
	if !strings.Contains(output, "should appear") {
		t.Fatal("sub-logger should log at parent level")
	}
}

func TestSubLoggerEnabled(t *testing.T) {
	l := &Logger{level: levelWarn}
	sub := l.With("X", "1")
	if sub.Enabled(levelDebug) {
		t.Fatal("Enabled(debug) should be false at warn level")
	}
	if !sub.Enabled(levelWarn) {
		t.Fatal("Enabled(warn) should be true at warn level")
	}
}
