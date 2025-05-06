package server

import (
	"time"
)

type state struct {
	UUID        string
	redirectURL string
	ctime       time.Time
}

type stateStorage interface {
	// Get returns the current state of the server.
	Get(id string) *state

	// Put sets the current state of the server.
	Put(state *state)
	Delete(id string)
}

type memoryStateStorage struct {
	// todo concurrent map
	states map[string]*state
}

func newMemoryStateStorage() *memoryStateStorage {
	// todo : add a cleanup routine to remove old states
	s := &memoryStateStorage{
		states: make(map[string]*state),
	}

	go func(s *memoryStateStorage) {
		for {
			time.Sleep(1 * time.Minute)
			for id, state := range s.states {
				if state.ctime.Before(time.Now().Add(-5 * time.Minute)) {
					s.Delete(id)
				}
			}
		}
	}(s)
	return s
}

func (m *memoryStateStorage) Get(id string) *state {
	return m.states[id]
}

func (m *memoryStateStorage) Put(state *state) {
	m.states[state.UUID] = state
}

func (m *memoryStateStorage) Delete(id string) {
	delete(m.states, id)
}
