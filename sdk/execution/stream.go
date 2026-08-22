package execution

// ChunkJSON splits data into chunks of chunkSize bytes.
// ponytail: ceiling is chunked JSON + flush on close; no framing/compression yet.
func ChunkJSON(data []byte, chunkSize int) [][]byte {
	if len(data) == 0 || chunkSize <= 0 {
		return nil
	}
	var out [][]byte
	for len(data) > 0 {
		n := chunkSize
		if n > len(data) {
			n = len(data)
		}
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}
