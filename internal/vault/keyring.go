package vault

import (
	"errors"
	"fmt"
	"sort"

	"filippo.io/age"
	"github.com/awnumar/memguard"
)

// Keyring implementation. Each unlocked identity is sealed in its own
// memguard enclave (encrypted in memory, D4); an operation opens it into a
// locked buffer for its duration only. Drop forgets the enclave: without
// it the identity cannot be recovered through the Keyring.

func newKeyring() *Keyring { return &Keyring{enclaves: map[string]*memguard.Enclave{}} }

func (k *Keyring) put(id string, identity *memguard.LockedBuffer) error {
	if k == nil {
		return errors.New("vault: nil keyring")
	}
	if identity == nil || !identity.IsAlive() {
		return errBadIdentity
	}
	if !validVaultID(id) {
		identity.Destroy()
		return fmt.Errorf("vault: bad vault id %q", id)
	}
	canon, err := normalizeIdentity(identity.Bytes())
	identity.Destroy()
	if err != nil {
		return err
	}
	e := canon.Seal() // destroys canon
	if e == nil {
		return errors.New("vault: cannot seal the identity")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.enclaves == nil {
		k.enclaves = map[string]*memguard.Enclave{}
	}
	k.enclaves[id] = e
	return nil
}

func (k *Keyring) has(id string) bool {
	if k == nil {
		return false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	_, ok := k.enclaves[id]
	return ok
}

func (k *Keyring) drop(id string) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.enclaves, id)
}

func (k *Keyring) dropAll() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	clear(k.enclaves)
}

func (k *Keyring) ids() []string {
	if k == nil {
		return nil
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	ids := make([]string, 0, len(k.enclaves))
	for id := range k.enclaves {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// open decrypts vault id's enclave into a locked buffer the caller
// destroys.
func (k *Keyring) open(id string) (*memguard.LockedBuffer, error) {
	if k == nil {
		return nil, ErrLocked
	}
	k.mu.RLock()
	e, ok := k.enclaves[id]
	k.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrLocked, id)
	}
	b, err := e.Open()
	if err != nil {
		return nil, fmt.Errorf("vault: cannot open the identity of %s", id)
	}
	return b, nil
}

func (k *Keyring) fileKey(id string, header []byte) (*memguard.LockedBuffer, error) {
	b, err := k.open(id)
	if err != nil {
		return nil, err
	}
	defer b.Destroy()
	ident, err := parseIdentity(b)
	if err != nil {
		return nil, err
	}
	key, err := age.DecryptHeader(header, ident)
	if err != nil {
		var nomatch *age.NoIdentityMatchError
		if errors.As(err, &nomatch) {
			return nil, fmt.Errorf("%w: the capsule is not sealed to vault %s", ErrWrongIdentity, id)
		}
		return nil, fmt.Errorf("%w: capsule header did not authenticate", ErrWrongIdentity)
	}
	return memguard.NewBufferFromBytes(key), nil // wipes key
}

func (k *Keyring) mac(id, info string, data []byte) (string, error) {
	b, err := k.open(id)
	if err != nil {
		return "", err
	}
	defer b.Destroy()
	return macWith(b, info, data)
}

func (k *Keyring) withIdentity(id string, fn func(age.Identity, *memguard.LockedBuffer) error) error {
	if fn == nil {
		return errors.New("vault: WithIdentity needs a function")
	}
	b, err := k.open(id)
	if err != nil {
		return err
	}
	defer b.Destroy()
	ident, err := parseIdentity(b)
	if err != nil {
		return err
	}
	return fn(ident, b)
}
