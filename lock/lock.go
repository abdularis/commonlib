package lock

type (
	// Locker interface to acquire named lock
	Locker interface {
		Acquire(name string) (Lock, error)
	}

	// Lock represent a single lock which can be released
	Lock interface {
		Release() error
	}
)
