package server

import "fmt"

// Error creates a new HTTPError by wrapping err with an HTTP status code.
func Error(code int, err error) error {
	return HTTPError{Code: code, Err: err}
}

// An HTTPError represents an error that occurred during the server's operation.
// It wraps an internal error with a status code that should be sent to the client when the error is rendered.
type HTTPError struct {
	Code int
	Err  error
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Err)
}

func (e HTTPError) Unwrap() error {
	return e.Err
}
