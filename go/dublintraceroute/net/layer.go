package net

// Layer is a serializable interface that support chaining.
type Layer interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	Next() Layer
	SetNext(Layer)
}
