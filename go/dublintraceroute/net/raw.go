package net

// Raw is a raw payload
type Raw struct {
	Data []byte
}

// NewRaw builds a new Raw layer
func NewRaw(b []byte) (*Raw, error) {
	var r Raw
	if err := r.Unmarshal(b); err != nil {
		return nil, err
	}
	return &r, nil
}

// Next returns the next layer. For Raw the next layer is always nil
func (r Raw) Next() Layer {
	return nil
}

// SetNext sets the next layer. For Raw this is a no op
func (r Raw) SetNext(Layer) {}

// Marshal serializes the layer
func (r Raw) Marshal() ([]byte, error) {
	return r.Data, nil
}

// Unmarshal deserializes the layer
func (r *Raw) Unmarshal(b []byte) error {
	r.Data = b
	return nil
}
