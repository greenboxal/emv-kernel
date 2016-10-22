package emv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
)

type Tlv map[int][]byte

func (t Tlv) Unmarshal(obj interface{}) error {
	value := reflect.ValueOf(obj)

	switch value.Kind() {
	case reflect.Ptr, reflect.Interface:
		value = value.Elem()
	}

	if !value.CanSet() {
		return fmt.Errorf("go type '%s' is read-only", value.Type())
	}

	typ := value.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := value.Field(i)
		fieldDef := typ.Field(i)

		opts, ok := fieldDef.Tag.Lookup("tlv")

		if !ok {
			continue
		}

		if opts == "other" {
			field.Set(reflect.ValueOf(t))
		} else {
			tag, err := strconv.ParseUint(opts, 16, 64)

			if err != nil {
				return err
			}

			_, err = t.UnmarshalValue(int(tag), field.Addr().Interface())

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (t Tlv) UnmarshalValue(tag int, value interface{}) (bool, error) {
	data, found := t[tag]

	if !found {
		return false, nil
	}

	b := bytes.NewBuffer(data)
	reflectedValue := reflect.ValueOf(value)

	switch reflectedValue.Kind() {
	case reflect.Ptr, reflect.Interface:
		reflectedValue = reflectedValue.Elem()
	}

	if !reflectedValue.CanSet() {
		return true, fmt.Errorf("go type '%s' is read-only", reflectedValue.Type())
	}

	typ := reflectedValue.Type()

	switch typ.Kind() {
	case reflect.Struct:
		result, err := DecodeTlv(data)

		if err != nil {
			return true, err
		}

		err = result.Unmarshal(value)

		if err != nil {
			return true, err
		}
	default:
		switch v := value.(type) {
		case TlvDecoder:
			err := v.DecodeTlv(data)

			if err != nil {
				return true, err
			}
		case *Tlv:
			result, err := DecodeTlv(data)

			if err != nil {
				return true, err
			}

			*v = result
		case *[]byte:
			*v = data
		case *int:
			result, err := binary.ReadVarint(b)

			if err != nil {
				return true, err
			}

			*v = int(result)
		case *int64:
			result, err := binary.ReadVarint(b)

			if err != nil {
				return true, err
			}

			*v = result
		case *uint64:
			result, err := binary.ReadUvarint(b)

			if err != nil {
				return true, err
			}

			*v = result
		case *uint:
			result, err := binary.ReadUvarint(b)

			if err != nil {
				return true, err
			}

			*v = uint(result)
		case *string:
			*v = string(data)
		case *bool:
			result, err := binary.ReadUvarint(b)

			if err != nil {
				return true, err
			}

			*v = result != 0
		default:
			return true, fmt.Errorf("go type %s can't be decoded", typ.Name())
		}
	}

	return true, nil
}

func (t Tlv) Tlv(tag int) (Tlv, bool, error) {
	result := make(Tlv)
	found, err := t.UnmarshalValue(tag, &result)

	if !found || err != nil {
		return nil, found, err
	}

	return result, true, nil
}

func (t Tlv) Uint(tag int) (uint64, bool, error) {
	result := uint64(0)
	found, err := t.UnmarshalValue(tag, &result)

	if !found || err != nil {
		return 0, found, err
	}

	return result, true, nil
}

func (t Tlv) Int(tag int) (int64, bool, error) {
	result := int64(0)
	found, err := t.UnmarshalValue(tag, &result)

	if !found || err != nil {
		return 0, found, err
	}

	return result, true, nil
}

func (t Tlv) String(tag int) (string, bool, error) {
	result := ""
	found, err := t.UnmarshalValue(tag, &result)

	if !found || err != nil {
		return "", found, err
	}

	return result, true, nil
}

func DecodeTlv(data []byte) (Tlv, error) {
	tlv := make(map[int][]byte)

	for i := 0; i < len(data); {
		tag, tagLength, err := DecodeTag(data[i:])

		if err != nil {
			return nil, err
		}

		i += tagLength

		length, lengthLength, err := DecodeLength(data[i:])

		if err != nil {
			return nil, err
		}

		i += lengthLength

		value := make([]byte, int(length))
		copy(value, data[i:i+int(length)])
		i += int(length)

		tlv[tag] = value
	}

	return Tlv(tlv), nil
}

func EncodeTlv(tlv Tlv) []byte {
	data := make([]byte, 0)

	for k, v := range tlv {
		data = append(data, EncodeTag(k)...)
		data = append(data, EncodeLength(uint64(len(v)))...)
		data = append(data, v...)
	}

	return data
}
