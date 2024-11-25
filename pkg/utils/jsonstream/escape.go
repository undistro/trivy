// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jsonstream

import "io"

type escapeWriter struct {
	scan   *scanner
	writer io.Writer
	escape bool
}

func newEscapeWriter(writer io.Writer, escape bool) *escapeWriter {
	return &escapeWriter{scan: newScanner(), writer: writer, escape: escape}
}

func (ew *escapeWriter) Write(src []byte) (int, error) {
	for i, c := range src {
		var err error
		if ew.escape && (c == '<' || c == '>' || c == '&') {
			_, err = ew.writer.Write([]byte{'\\', 'u', '0', '0', hex[c>>4], hex[c&0xF]})
		} else if ew.escape && c == 0xE2 && i+2 < len(src) && src[i+1] == 0x80 && src[i+2]&^1 == 0xA8 {
			// Convert U+2028 and U+2029 (E2 80 A8 and E2 80 A9).
			_, err = ew.writer.Write([]byte{'\\', 'u', '2', '0', '2', hex[src[i+2]&0xF]})
		} else {
			_, err = ew.writer.Write([]byte{c})
		}
		if err != nil {
			return i, err
		}
		v := ew.scan.step(ew.scan, c)
		if v == scanError {
			return i, ew.scan.err
		}
	}
	return len(src), nil
}

func (ew *escapeWriter) checkEnd() error {
	if ew.scan.eof() == scanError {
		return ew.scan.err
	}
	return nil
}
