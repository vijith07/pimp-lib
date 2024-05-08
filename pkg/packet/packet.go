package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

type DataPacket struct {
	Version byte
	Type    byte
	Payload []byte
}

func Encode(packet DataPacket) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, packet.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, packet.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(len(packet.Payload))); err != nil {
		return nil, err
	}

	// Encode payload
	if _, err := buf.Write(packet.Payload); err != nil {
		return nil, err
	}

	// Calculate and encode checksum
	checksum := crc32.ChecksumIEEE(buf.Bytes())
	if err := binary.Write(buf, binary.BigEndian, checksum); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func Decode(data []byte) (*DataPacket, error) {
	buf := bytes.NewReader(data)
	packet := &DataPacket{}

	// Decode header
	if err := binary.Read(buf, binary.BigEndian, &packet.Version); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &packet.Type); err != nil {
		return nil, err
	}

	var length uint16
	if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	// Decode payload
	packet.Payload = make([]byte, length)
	if err := binary.Read(buf, binary.BigEndian, &packet.Payload); err != nil {
		return nil, err
	}

	// Decode and check checksum
	var receivedChecksum uint32
	if err := binary.Read(buf, binary.BigEndian, &receivedChecksum); err != nil {
		return nil, err
	}
	calculatedChecksum := crc32.ChecksumIEEE(data[:len(data)-4])
	if receivedChecksum != calculatedChecksum {
		return nil, errors.New("checksum mismatch")
	}

	return packet, nil
}
