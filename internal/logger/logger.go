// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	name           string
	level          int
	mu             sync.Mutex
	consoleWriter  io.Writer
	fileWriter     *os.File
	color          bool
	appNameText    string
	appNameColored string
}

const (
	levelDebug = iota
	levelInfo
	levelWarn
	levelError
)

const (
	LevelDebug = levelDebug
	LevelInfo  = levelInfo
	LevelWarn  = levelWarn
	LevelError = levelError
)

var colorTagCodes = map[string]string{
	"black":   "\x1b[30m",
	"red":     "\x1b[31m",
	"green":   "\x1b[32m",
	"yellow":  "\x1b[33m",
	"blue":    "\x1b[34m",
	"magenta": "\x1b[35m",
	"cyan":    "\x1b[36m",
	"white":   "\x1b[37m",
	"gray":    "\x1b[90m",
	"grey":    "\x1b[90m",
	"bold":    "\x1b[1m",
	"reset":   "\x1b[0m",
}

var plainLevelTexts = [...]string{
	levelDebug: "[DEBUG]",
	levelInfo:  "[INFO]",
	levelWarn:  "[WARN]",
	levelError: "[ERROR]",
}

var coloredLevelTexts = [...]string{
	levelDebug: "\x1b[35m[DEBUG]\x1b[0m",
	levelInfo:  "\x1b[32m[INFO]\x1b[0m",
	levelWarn:  "\x1b[33m[WARN]\x1b[0m",
	levelError: "\x1b[31m[ERROR]\x1b[0m",
}

func New(name, rawLevel string) *Logger {
	return NewWithFile(name, rawLevel, "")
}

func NewWithFile(name, rawLevel, filePath string) *Logger {
	appName := "[" + name + "]"
	var consoleWriter io.Writer = os.Stdout
	var fileWriter *os.File

	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			fileWriter = f
		}
	}

	return &Logger{
		name:           name,
		level:          parseLevel(rawLevel),
		consoleWriter:  consoleWriter,
		fileWriter:     fileWriter,
		color:          shouldUseColor(),
		appNameText:    appName,
		appNameColored: "\x1b[36m" + appName + "\x1b[0m",
	}
}

func parseLevel(raw string) int {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "DEBUG":
		return levelDebug
	case "WARNING", "WARN":
		return levelWarn
	case "ERROR", "CRITICAL":
		return levelError
	default:
		return levelInfo
	}
}

func (l *Logger) logf(level int, format string, args ...any) {
	if l == nil || level < l.level {
		return
	}

	msg := format
	if len(args) != 0 {
		msg = fmt.Sprintf(format, args...)
	}

	plainMsg := msg
	if strings.IndexByte(msg, '<') >= 0 {
		plainMsg = stripColorTags(msg)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().Format("2006/01/02 15:04:05")

	if l.fileWriter != nil {
		fileLine := ts + " " + plainLevelTexts[level] + " " + plainMsg + "\n"
		if _, err := io.WriteString(l.fileWriter, fileLine); err != nil {
			_ = l.fileWriter.Close()
			l.fileWriter = nil
		}
	}

	if l.consoleWriter != nil {
		appName := l.appNameText
		levelText := plainLevelTexts[level]
		finalMsg := plainMsg

		if l.color {
			if strings.IndexByte(msg, '<') >= 0 {
				finalMsg = renderColorTags(msg)
			} else {
				finalMsg = msg
			}
			appName = l.appNameColored
			levelText = coloredLevelTexts[level]
		}

		consoleLine := ts + " " + appName + " " + levelText + " " + finalMsg + "\n"
		_, _ = io.WriteString(l.consoleWriter, consoleLine)
	}
}

func (l *Logger) Debugf(format string, args ...any) { l.logf(levelDebug, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.logf(levelInfo, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.logf(levelWarn, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.logf(levelError, format, args...) }

func (l *Logger) Enabled(level int) bool {
	return l != nil && level >= l.level
}

// SubLogger wraps a Logger with a pre-rendered context prefix (e.g. "[Sess:3] [Str:42]").
// It satisfies the arq.Logger interface and can be chained via With().
type SubLogger struct {
	parent *Logger
	prefix string
}

// With creates a SubLogger with a single [key:value] context field.
func (l *Logger) With(key, value string) *SubLogger {
	return &SubLogger{parent: l, prefix: "[" + key + ":" + value + "]"}
}

// With chains an additional [key:value] context field onto an existing SubLogger.
func (s *SubLogger) With(key, value string) *SubLogger {
	return &SubLogger{parent: s.parent, prefix: s.prefix + " [" + key + ":" + value + "]"}
}

func (s *SubLogger) Debugf(format string, args ...any) {
	s.parent.logf(levelDebug, s.prefix+" "+format, args...)
}
func (s *SubLogger) Infof(format string, args ...any) {
	s.parent.logf(levelInfo, s.prefix+" "+format, args...)
}
func (s *SubLogger) Warnf(format string, args ...any) {
	s.parent.logf(levelWarn, s.prefix+" "+format, args...)
}
func (s *SubLogger) Errorf(format string, args ...any) {
	s.parent.logf(levelError, s.prefix+" "+format, args...)
}

func (s *SubLogger) Enabled(level int) bool {
	return s.parent.Enabled(level)
}

func stripColorTags(text string) string {
	start := strings.IndexByte(text, '<')
	if start == -1 {
		return text
	}

	var b strings.Builder
	b.Grow(len(text))

	for i := 0; i < len(text); {
		if text[i] != '<' {
			next := strings.IndexByte(text[i:], '<')
			if next == -1 {
				b.WriteString(text[i:])
				break
			}
			b.WriteString(text[i : i+next])
			i += next
			continue
		}

		end := strings.IndexByte(text[i:], '>')
		if end == -1 {
			b.WriteString(text[i:])
			break
		}

		rawTag := text[i : i+end+1]
		tag := strings.ToLower(rawTag)
		if _, _, ok := parseColorTag(tag); ok {
			i += end + 1
			continue
		}

		b.WriteString(rawTag)
		i += end + 1
	}

	return b.String()
}

func shouldUseColor() bool {
	if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
		return false
	}
	if strings.TrimSpace(os.Getenv("FORCE_COLOR")) != "" {
		return true
	}
	return detectColorSupport(os.Stdout)
}

func renderColorTags(text string) string {
	start := strings.IndexByte(text, '<')
	if start == -1 {
		return text
	}

	var b strings.Builder
	b.Grow(len(text) + 16)
	b.WriteString(text[:start])
	stack := make([]string, 0, 4)

	for i := start; i < len(text); {
		if text[i] != '<' {
			next := strings.IndexByte(text[i:], '<')
			if next == -1 {
				b.WriteString(text[i:])
				break
			}
			b.WriteString(text[i : i+next])
			i += next
			continue
		}

		end := strings.IndexByte(text[i:], '>')
		if end == -1 {
			b.WriteString(text[i:])
			break
		}

		rawTag := text[i : i+end+1]
		tag := strings.ToLower(rawTag)
		if name, closing, ok := parseColorTag(tag); ok {
			if closing {
				if name == "reset" {
					stack = stack[:0]
					b.WriteString("\x1b[0m")
				} else if restoreColorTag(&stack, name) {
					b.WriteString("\x1b[0m")
					for _, active := range stack {
						b.WriteString(colorTagCodes[active])
					}
				} else {
					b.WriteString(rawTag)
				}
			} else {
				stack = append(stack, name)
				b.WriteString(colorTagCodes[name])
			}
		} else {
			b.WriteString(rawTag)
		}
		i += end + 1
	}

	if len(stack) != 0 {
		b.WriteString("\x1b[0m")
	}

	return b.String()
}

func parseColorTag(tag string) (name string, closing bool, ok bool) {
	if len(tag) < 3 || tag[0] != '<' || tag[len(tag)-1] != '>' {
		return "", false, false
	}
	closing = strings.HasPrefix(tag, "</")
	if closing {
		name = tag[2 : len(tag)-1]
	} else {
		name = tag[1 : len(tag)-1]
	}
	_, ok = colorTagCodes[name]
	return name, closing, ok
}

func restoreColorTag(stack *[]string, name string) bool {
	if stack == nil || len(*stack) == 0 {
		return false
	}
	items := *stack
	for idx := len(items) - 1; idx >= 0; idx-- {
		if items[idx] != name {
			continue
		}
		copy(items[idx:], items[idx+1:])
		lastIdx := len(items) - 1
		items[lastIdx] = ""
		*stack = items[:lastIdx]
		return true
	}
	return false
}

func NowUnixNano() int64 {
	return time.Now().UnixNano()
}
