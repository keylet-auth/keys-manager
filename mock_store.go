package keys_manager

import "sync"

type MockStore struct {
	mu   sync.Mutex
	data map[string]*Key
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

func (s *MockStore) GetByKID(kid string) (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[kid], nil
}

func (s *MockStore) Rotate(newKey *Key, old *Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if old != nil {
		if stored, ok := s.data[old.KID]; ok {
			stored.IsActive = false
		}
	}

	s.data[newKey.KID] = newKey
	return nil
}
