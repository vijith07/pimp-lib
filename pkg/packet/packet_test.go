package packet

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"reflect"
	"testing"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		name    string
		packet  DataPacket
		want    []byte
		wantErr bool
	}{
		{
			name: "Normal case",
			packet: DataPacket{
				Version: 1,
				Type:    1,
				Payload: []byte("Hello, World!"),
			},
			want:    prepareEncodedData(1, 1, []byte("Hello, World!")),
			wantErr: false,
		},
		{
			name: "Empty payload",
			packet: DataPacket{
				Version: 1,
				Type:    1,
				Payload: []byte(""),
			},
			want:    prepareEncodedData(1, 1, []byte("")),
			wantErr: false,
		},
		{
			name: "Large payload",
			packet: DataPacket{
				Version: 1,
				Type:    1,
				Payload: bytes.Repeat([]byte("a"), 65535),
			},
			want:    prepareEncodedData(1, 1, bytes.Repeat([]byte("a"), 65535)),
			wantErr: false,
		},
		{
			name: "Boundary conditions for type",
			packet: DataPacket{
				Version: 1,
				Type:    255,
				Payload: []byte("Boundary test"),
			},
			want:    prepareEncodedData(1, 255, []byte("Boundary test")),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Encode(tt.packet)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Encode() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to prepare encoded data with checksum, identical to usage in Decode tests
func prepareEncodedData(version byte, msgType byte, payload []byte) []byte {
	buf := bytes.Buffer{}
	binary.Write(&buf, binary.BigEndian, version)
	binary.Write(&buf, binary.BigEndian, msgType)
	binary.Write(&buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(payload)

	checksum := crc32.ChecksumIEEE(buf.Bytes())
	binary.Write(&buf, binary.BigEndian, checksum)

	return buf.Bytes()
}

// TestDecode function with multiple cases
func TestDecode(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *DataPacket
		wantErr bool
	}{
		{
			name:    "Normal case",
			input:   prepareEncodedData(1, 1, []byte("Hello")),
			want:    &DataPacket{Version: 1, Type: 1, Payload: []byte("Hello")},
			wantErr: false,
		},
		{
			name:    "Empty payload",
			input:   prepareEncodedData(1, 1, []byte("")),
			want:    &DataPacket{Version: 1, Type: 1, Payload: []byte("")},
			wantErr: false,
		},
		{
			name:    "Large payload",
			input:   prepareEncodedData(1, 1, bytes.Repeat([]byte("a"), 65535)),
			want:    &DataPacket{Version: 1, Type: 1, Payload: bytes.Repeat([]byte("a"), 65535)},
			wantErr: false,
		},
		{
			name:    "Incorrect checksum",
			input:   append(prepareEncodedData(1, 1, []byte("Hello"))[:len(prepareEncodedData(1, 1, []byte("Hello")))-4], []byte{0, 0, 0, 0}...),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Corrupted data (short length)",
			input:   []byte{1, 1, 0},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got.Payload, tt.want.Payload) {
				t.Errorf("Decode() got = %v, want %v", got, tt.want)
			}
		})
	}
}
