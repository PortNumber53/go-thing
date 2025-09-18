package tools

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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
	containerName, err := EnsureDockerContainer()
	if err != nil {
		return nil, fmt.Errorf("ensure container: %w", err)
	}
	return b.createOrGetWithContainer(containerName, id, subdir)
}

// CreateOrGetInContainer is like CreateOrGet but attaches to a specific container name.
// The caller is responsible for ensuring the container exists and is running.
func (b *ShellBroker) CreateOrGetInContainer(containerName string, id string, subdir string) (*ShellSession, error) {
	return b.createOrGetWithContainer(containerName, id, subdir)
}

// createOrGetWithContainer centralizes session creation/lookup given a container name.
// It acquires the broker lock, validates inputs, prepares workdir, starts PTY, and
// registers the session. Callers should pass an already ensured container name.
func (b *ShellBroker) createOrGetWithContainer(containerName string, id string, subdir string) (*ShellSession, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("session id required")
	}
	if strings.TrimSpace(containerName) == "" {
		return nil, errors.New("container name required")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.sessions[id]; ok {
		return s, nil
	}

	workdir := "/app"
	if sub := strings.TrimSpace(subdir); sub != "" {
		// Sanitize the subdirectory path to prevent path traversal attacks.
		joinedPath := filepath.Join("/app", sub)
		if !strings.HasPrefix(joinedPath, "/app/") && joinedPath != "/app" {
			return nil, fmt.Errorf("invalid subdir, potential path traversal: %q", sub)
		}
		workdir = filepath.ToSlash(joinedPath)
	}

	// docker exec with TTY; attach a real PTY so the shell is truly interactive
	execArgs := []string{"exec", "-i", "-t", "-w", workdir, "-e", "TERM=xterm-256color", "-e", "COLORTERM=truecolor", "-e", "LC_ALL=C.UTF-8", containerName, "/bin/bash", "-i"}
	cmd := exec.Command("docker", execArgs...)
	cmd.Env = []string{}
	tty, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("start docker exec PTY: %w", err)
	}

	s := &ShellSession{
		ID:          id,
		Workdir:     workdir,
		cmd:         cmd,
		tty:         tty,
		inputQueue:  make(chan []byte, 4096),
		subscribers: make(map[chan []byte]struct{}),
		closed:      make(chan struct{}),
	}
	b.sessions[id] = s
	log.Printf("[Shell] session %s started: workdir=%s container=%s", id, workdir, containerName)
	go s.run()
	go func() {
		if err := s.cmd.Wait(); err != nil {
			log.Printf("[Shell %s] command process exited with error: %v", s.ID, err)
		}
		s.Close()
	}()
	return s, nil
}

// CreateOrGetInContainer is like CreateOrGet but attaches to a specific container name.
// The caller is responsible for ensuring the container exists and is running.
// (duplicate CreateOrGetInContainer removed)

// Get returns a session by id.
func (b *ShellBroker) Get(id string) (*ShellSession, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	s, ok := b.sessions[id]
	return s, ok
}

// List returns active session IDs.
func (b *ShellBroker) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.sessions))
	for id := range b.sessions {
		out = append(out, id)
	}
	return out
}

// Close terminates and removes a session.
func (b *ShellBroker) Close(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[id]
	if !ok {
		return nil
	}
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
// It is non-blocking and returns false if the input queue is full so callers can handle backpressure.
func (s *ShellSession) Enqueue(data []byte) bool {
	select {
	case s.inputQueue <- data:
		return true
	default:
		return false
	}
}

// Subscribe returns a channel to receive broadcast output. Call Unsubscribe when done.
func (s *ShellSession) Subscribe() chan []byte {
	ch := make(chan []byte, 256)
	s.subsMu.Lock()
	defer s.subsMu.Unlock()

	// If session is already closing, return a closed channel immediately
	// to prevent new subscribers from attaching to a defunct session.
	select {
	case <-s.closed:
		close(ch)
		return ch
	default:
	}

	s.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a subscriber and closes its channel.
func (s *ShellSession) Unsubscribe(ch chan []byte) {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	if _, ok := s.subscribers[ch]; ok {
		delete(s.subscribers, ch)
		close(ch)
	}
}

// Close signals the session to terminate.
func (s *ShellSession) Close() {
	s.onceClose.Do(func() {
		close(s.closed)
		// Attempt polite exit
		_ = s.write([]byte("exit\n"))
		// Give the shell a moment
		time.AfterFunc(500*time.Millisecond, func() { _ = s.cmd.Process.Kill() })

		// Notify and unblock all subscribers to prevent goroutine leaks.
		s.subsMu.Lock()
		for ch := range s.subscribers {
			close(ch)
		}
		// Reset the map so Unsubscribe won't act on closed channels.
		s.subscribers = make(map[chan []byte]struct{})
		s.subsMu.Unlock()
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
			// Batch drain queued inputs to reduce backpressure
			buf := make([]byte, 0, len(data)+4096)
			buf = append(buf, data...)
			drain := true
			for drain {
				select {
				case more := <-s.inputQueue:
					buf = append(buf, more...)
					// avoid runaway buffers; write in chunks if very large
					if len(buf) > 64*1024 {
						_ = s.write(buf)
						buf = buf[:0]
					}
				default:
					drain = false
				}
			}
			if len(buf) > 0 {
				_ = s.write(buf)
			}
		}
	}
}

func (s *ShellSession) write(data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	n, err := s.tty.Write(data)
	if err != nil {
		log.Printf("[Shell %s] write error: %v", s.ID, err)
	} else {
		log.Printf("[Shell %s] wrote %d bytes", s.ID, n)
	}
	return err
}

// Resize changes the PTY window size for the session.
func (s *ShellSession) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	ws := &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)}
	f, ok := s.tty.(*os.File)
	if !ok {
		return fmt.Errorf("tty is not *os.File")
	}
	if err := pty.Setsize(f, ws); err != nil {
		log.Printf("[Shell %s] resize error: %v", s.ID, err)
		return err
	}
	// Trigger docker exec client to forward new size to container
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(syscall.SIGWINCH)
	}
	return nil
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
			// Avoid logging raw payload to prevent potential secret leakage.
			log.Printf("[Shell %s] read %d bytes", s.ID, n)
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
		select {
		case ch <- data:
		default: /* drop if slow */
		}
	}
	s.subsMu.Unlock()
}
