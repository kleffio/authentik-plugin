package domain

import "errors"

// ErrUnauthorized is returned when credentials are invalid or a token fails verification.
type ErrUnauthorized struct{ Msg string }

func (e *ErrUnauthorized) Error() string { return e.Msg }

// ErrNotSupported is returned for operations Authentik cannot handle via this plugin.
type ErrNotSupported struct{ Msg string }

func (e *ErrNotSupported) Error() string { return e.Msg }

// ErrConflict is returned when a resource already exists (e.g. duplicate username).
type ErrConflict struct{ Msg string }

func (e *ErrConflict) Error() string { return e.Msg }

// IsUnauthorized reports whether err is or wraps ErrUnauthorized.
func IsUnauthorized(err error) bool {
	var e *ErrUnauthorized
	return errors.As(err, &e)
}

// IsNotSupported reports whether err is or wraps ErrNotSupported.
func IsNotSupported(err error) bool {
	var e *ErrNotSupported
	return errors.As(err, &e)
}

// IsConflict reports whether err is or wraps ErrConflict.
func IsConflict(err error) bool {
	var e *ErrConflict
	return errors.As(err, &e)
}
