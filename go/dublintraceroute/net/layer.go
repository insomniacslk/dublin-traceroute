package net

// Layer is a serializable interface that support chaining.
type Layer interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary(data []byte) error
	Next() Layer
	SetNext(Layer)
}
