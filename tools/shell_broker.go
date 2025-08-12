package tools

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
)

// ShellBroker manages multiple long-lived interactive shell sessions inside the docker container.
// Each session runs a single /bin/bash with a TTY and preserves state across inputs.
// Outputs are broadcast to all subscribers; inputs are serialized via a FIFO channel.

type ShellBroker struct {
	mu       sync.RWMutex
	sessions map[string]*ShellSession
}

var (
	brokerOnce sync.Once
	brokerInst *ShellBroker
)

// GetShellBroker returns the singleton broker instance.
func GetShellBroker() *ShellBroker {
	brokerOnce.Do(func() {
		brokerInst = &ShellBroker{sessions: make(map[string]*ShellSession)}
	})
	return brokerInst
}

// ShellSession represents a persistent interactive shell.
// Use Subscribe to receive output; send input via Enqueue.

type ShellSession struct {
	ID          string
	Workdir     string // container workdir, default "/app"
	cmd         *exec.Cmd
	tty         io.ReadWriteCloser
	inputQueue  chan []byte
	subsMu      sync.Mutex
	writeMu     sync.Mutex
	subscribers map[chan []byte]struct{}
	closed      chan struct{}
	onceClose   sync.Once
}

// CreateOrGet starts (or returns) a session with the given id and optional subdir inside CHROOT_DIR.
// subdir may be empty; when provided, it is joined to CHROOT_DIR and mapped to /app/<subdir> in container.
func (b *ShellBroker) CreateOrGet(id string, subdir string) (*ShellSession, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("session id required")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.sessions[id]; ok {
		return s, nil
	}

	containerName, err := EnsureDockerContainer()
	if err != nil {
		return nil, fmt.Errorf("ensure container: %w", err)
	}

	workdir := "/app"
    if sub := strings.TrimSpace(subdir); sub != "" {
        // Sanitize the subdirectory path to prevent path traversal attacks.
        // filepath.Join will resolve elements like ".." and create a canonical path.
        joinedPath := filepath.Join("/app", sub)

        // Ensure the resulting path is still within the intended /app directory.
        if !strings.HasPrefix(joinedPath, "/app/") && joinedPath != "/app" {
            return nil, fmt.Errorf("invalid subdir, potential path traversal: %q", sub)
        }
        workdir = filepath.ToSlash(joinedPath)
    }

	// docker exec with TTY; attach a real PTY so the shell is truly interactive
	execArgs := []string{"exec", "-i", "-t", "-w", workdir, containerName, "/bin/bash"}
	cmd := exec.Command("docker", execArgs...)
	// Clear env for safety
	cmd.Env = []string{}
	// Start the command with an attached PTY
	tty, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("start docker exec PTY: %w", err)
	}

	s := &ShellSession{
		ID:          id,
		Workdir:     workdir,
		cmd:         cmd,
		tty:         tty,
		inputQueue:  make(chan []byte, 256),
		subscribers: make(map[chan []byte]struct{}),
		closed:      make(chan struct{}),
	}
	b.sessions[id] = s
	log.Printf("[Shell] session %s started: workdir=%s container=%s", id, workdir, containerName)
	go s.run()
	return s, nil
}

// Get returns a session by id.
func (b *ShellBroker) Get(id string) (*ShellSession, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	s, ok := b.sessions[id]
	return s, ok
}

// List returns active session IDs.
func (b *ShellBroker) List() []string {
	b.mu.RLock(); defer b.mu.RUnlock()
	out := make([]string, 0, len(b.sessions))
	for id := range b.sessions { out = append(out, id) }
	return out
}

// Close terminates and removes a session.
func (b *ShellBroker) Close(id string) error {
	b.mu.Lock(); defer b.mu.Unlock()
	s, ok := b.sessions[id]
	if !ok { return nil }
	s.Close()
	delete(b.sessions, id)
	return nil
}

// CloseAll terminates all active sessions under a single lock.
func (b *ShellBroker) CloseAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, s := range b.sessions {
		s.Close()
		delete(b.sessions, id)
	}
	log.Printf("[Shell] Closed all active sessions.")
}

// Enqueue writes data (appends newline if desired by caller) to the session's stdin serially.
func (s *ShellSession) Enqueue(data []byte) { s.inputQueue <- data }

// Subscribe returns a channel to receive broadcast output. Call Unsubscribe when done.
func (s *ShellSession) Subscribe() chan []byte {
	ch := make(chan []byte, 256)
	s.subsMu.Lock(); s.subscribers[ch] = struct{}{}; s.subsMu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (s *ShellSession) Unsubscribe(ch chan []byte) {
	s.subsMu.Lock(); if _, ok := s.subscribers[ch]; ok { delete(s.subscribers, ch); close(ch) }; s.subsMu.Unlock()
}

// Close signals the session to terminate.
func (s *ShellSession) Close() {
	s.onceClose.Do(func() {
		close(s.closed)
		// Attempt polite exit
		_ = s.write([]byte("exit\n"))
		// Give the shell a moment
		time.AfterFunc(500*time.Millisecond, func() { _ = s.cmd.Process.Kill() })
	})
}

func (s *ShellSession) run() {
	// Reader goroutine: PTY -> broadcast (stdout+stderr merged)
	go s.readLoop(s.tty)
	// Writer loop: serialize inputs
	for {
		select {
		case <-s.closed:
			return
		case data := <-s.inputQueue:
			_ = s.write(data)
		}
	}
}

func (s *ShellSession) write(data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// Avoid partial writes; add CR if writing single lines without newline
	if len(data) > 0 {
		if !bytes.HasSuffix(data, []byte("\n")) {
			// For interactive shells, newline typically executes the command
			data = append(data, '\n')
		}
	}
	n, err := s.tty.Write(data)
	if err != nil {
		log.Printf("[Shell %s] write error: %v", s.ID, err)
	} else {
		log.Printf("[Shell %s] wrote %d bytes", s.ID, n)
	}
	return err
}

func (s *ShellSession) readLoop(r io.Reader) {
	br := bufio.NewReader(r)
	buf := make([]byte, 4096)
	for {
		select {
		case <-s.closed:
			return
		default:
		}
		// Read whatever is available; do not block forever on long lines
		n, err := br.Read(buf)
		if n > 0 {
			payload := make([]byte, n)
			copy(payload, buf[:n])
			log.Printf("[Shell %s] read %d bytes: %q", s.ID, n, string(payload))
			s.broadcast(payload)
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[Shell %s] read error, closing session: %v", s.ID, err)
				// Broadcast error as message before closing
				s.broadcast([]byte("\n[session error] " + err.Error() + "\n"))
			}
			// Ensure full session cleanup on any read error or EOF
			s.Close()
			return
		}
	}
}

func (s *ShellSession) broadcast(data []byte) {
	s.subsMu.Lock()
	for ch := range s.subscribers {
		select { case ch <- data: default: /* drop if slow */ }
	}
	s.subsMu.Unlock()
}
