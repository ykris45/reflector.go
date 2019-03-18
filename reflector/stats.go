package reflector

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lbryio/lbry.go/extras/errors"
	"github.com/lbryio/lbry.go/extras/stop"

	log "github.com/sirupsen/logrus"
)

// TODO: store daily stats too. and maybe other intervals

type Stats struct {
	mu      *sync.Mutex
	blobs   int
	streams int
	errors  map[string]int
	started bool

	name    string
	logger  *log.Logger
	logFreq time.Duration
	grp     *stop.Group
}

func NewStatLogger(name string, logger *log.Logger, logFreq time.Duration, parentGrp *stop.Group) *Stats {
	return &Stats{
		mu:      &sync.Mutex{},
		grp:     stop.New(parentGrp),
		logger:  logger,
		logFreq: logFreq,
		errors:  make(map[string]int),
		name:    name,
	}
}

func (s *Stats) Start() {
	s.started = true
	s.grp.Add(1)
	go func() {
		defer s.grp.Done()
		s.runSlackLogger()
	}()
}

func (s *Stats) Shutdown() {
	if !s.started {
		return
	}
	s.log()
	s.grp.StopAndWait()
	s.started = false
}

func (s *Stats) AddBlob() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs++
}
func (s *Stats) AddStream() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams++
}

func (s *Stats) AddError(e error) (shouldLog bool) { // shouldLog is a hack, but whatever
	if e == nil {
		return
	}
	err := errors.Wrap(e, 0)
	name := err.TypeName()
	if strings.Contains(err.Error(), "i/o timeout") { // hit a read or write deadline
		name = "i/o timeout"
	} else if strings.Contains(err.Error(), "read: connection reset by peer") { // the other side closed the connection using TCP reset
		name = "read conn reset"
	} else if strings.Contains(err.Error(), "unexpected EOF") { // tried to read from closed pipe or socket
		name = "unexpected EOF"
	} else if strings.Contains(err.Error(), "write: broken pipe") { // tried to write to a pipe or socket that was closed by the peer
		name = "write broken pipe"
	} else {
		shouldLog = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.errors[name]++
	return
}

func (s *Stats) runSlackLogger() {
	t := time.NewTicker(s.logFreq)
	for {
		select {
		case <-s.grp.Ch():
			return
		case <-t.C:
			s.log()
		}
	}
}

func (s *Stats) log() {
	s.mu.Lock()
	blobs, streams := s.blobs, s.streams
	s.blobs, s.streams = 0, 0
	errStr := ""
	for name, count := range s.errors {
		errStr += fmt.Sprintf("%d %s, ", count, name)
		delete(s.errors, name)
	}
	s.mu.Unlock()

	if len(errStr) > 2 {
		errStr = errStr[:len(errStr)-2] // trim last comma and space
	}

	s.logger.Printf("%s stats: %d blobs, %d streams, errors: %s", s.name, blobs, streams, errStr)
}
