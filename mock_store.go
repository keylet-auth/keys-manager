package keys_manager

import "sync"

type MockStore struct {
	mu          sync.Mutex
	data        map[string]*Key
	RotateCount int
	RotateErr   error
}

func NewMockStore() *MockStore {
	return &MockStore{data: make(map[string]*Key)}
}

func (s *MockStore) Save(key *Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key.KID] = key
	return nil
}

func (s *MockStore) List() ([]*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*Key, 0, len(s.data))
	for _, k := range s.data {
		out = append(out, k)
	}
	return out, nil
}

func (s *MockStore) Rotate(newKey *Key, old *Key) error {
	if s.RotateErr != nil {
		return s.RotateErr
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.RotateCount++

	if old != nil {
		if stored, ok := s.data[old.KID]; ok {
			stored.IsActive = false
		}
	}

	s.data[newKey.KID] = newKey
	return nil
}
