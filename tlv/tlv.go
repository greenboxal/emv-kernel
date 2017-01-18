package tlv

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type Tlv map[int][]byte

func Pick(tag int, tlvs ...Tlv) (Tlv, bool) {
	for _, t := range tlvs {
		_, found := t[tag]

		if found {
			return t, true
		}
	}

	return nil, false
}

func (tlv Tlv) CopyFrom(other Tlv) {
	for k, v := range other {
		tlv[k] = v
	}
}

func (tlv Tlv) DecodeTlv(data []byte) error {
	for i := 0; i < len(data); {
		tag, tagLength, err := DecodeTag(data[i:])

		if err != nil {
			return err
		}

		i += tagLength

		if tag == 0 {
			continue
		}

		length, lengthLength, err := DecodeLength(data[i:])

		if err != nil {
			return err
		}

		i += lengthLength

		value := make([]byte, int(length))
		copy(value, data[i:i+int(length)])
		i += int(length)

		tlv[tag] = value
	}

	return nil
}

func (tlv Tlv) EncodeTlv() ([]byte, error) {
	data := make([]byte, 0)

	for k, v := range tlv {
		data = append(data, EncodeTag(k)...)
		data = append(data, EncodeLength(uint64(len(v)))...)
		data = append(data, v...)
	}

	return data, nil
}

func (t Tlv) Marshal(obj interface{}) error {
	value := reflect.ValueOf(obj)

	switch value.Kind() {
	case reflect.Ptr, reflect.Interface:
		value = value.Elem()
	}

	typ := value.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := value.Field(i)
		fieldDef := typ.Field(i)

		structTag, ok := fieldDef.Tag.Lookup("tlv")
		opts := strings.Split(structTag, ",")

		if !ok {
			continue
		}

		if optsContains(opts, "other") {
			if !field.IsNil() {
				other := field.Interface().(Tlv)

				t.CopyFrom(other)
			}
		} else {
			tag, err := strconv.ParseUint(opts[0], 16, 64)

			if err != nil {
				return err
			}

			err = t.MarshalValueWithOptions(int(tag), field.Interface(), opts)

			if err != nil {
				return err
			}
		}
	}

	return nil
}

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

		structTag, ok := fieldDef.Tag.Lookup("tlv")
		opts := strings.Split(structTag, ",")

		if !ok {
			continue
		}

		if optsContains(opts, "other") {
			if field.IsNil() {
				field.Set(reflect.ValueOf(t))
			} else {
				other := field.Interface().(Tlv)

				other.CopyFrom(t)
			}
		} else {
			tag, err := strconv.ParseUint(opts[0], 16, 64)

			if err != nil {
				return err
			}

			_, err = t.UnmarshalValueWithOptions(int(tag), field.Addr().Interface(), opts)

			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (t Tlv) MarshalValue(tag int, value interface{}) error {
	return t.MarshalValueWithOptions(tag, value, []string{})
}

func (t Tlv) MarshalValueWithLength(tag, length int, value interface{}) error {
	return t.MarshalValueWithLengthAndOptions(tag, -1, value, []string{})
}

func (t Tlv) MarshalValueWithOptions(tag int, value interface{}, options []string) error {
	return t.MarshalValueWithLengthAndOptions(tag, -1, value, options)
}

func (t Tlv) MarshalValueWithLengthAndOptions(tag, length int, value interface{}, options []string) error {
	reflectedValue := reflect.ValueOf(value)

	switch reflectedValue.Kind() {
	case reflect.Ptr, reflect.Interface:
		reflectedValue = reflectedValue.Elem()
	}

	typ := reflectedValue.Type()

	encoder, ok := value.(TlvEncoder)

	if ok {
		data, err := encoder.EncodeTlv()

		if err != nil {
			return err
		}

		t[tag] = data

		return nil
	}

	switch typ.Kind() {
	case reflect.Struct:
		tlv := make(Tlv)

		err := tlv.Marshal(value)

		if err != nil {
			return err
		}

		data, err := tlv.EncodeTlv()

		if err != nil {
			return err
		}

		t[tag] = data
	default:
		switch v := value.(type) {
		case []byte:
			t[tag] = v
		case int:
			t[tag] = EncodeInteger(int64(v))
		case int64:
			t[tag] = EncodeInteger(v)
		case uint64:
			t[tag] = EncodeUInt(v)
		case uint:
			t[tag] = EncodeUInt(uint64(v))
		case string:
			if optsContains(options, "hex") {
				data, err := hex.DecodeString(v)

				if err != nil {
					return err
				}

				t[tag] = data
			} else {
				t[tag] = []byte(v)
			}
		case bool:
			i := 0

			if v {
				i = 1
			}

			t[tag] = EncodeUInt(uint64(i))
		default:
			return fmt.Errorf("go type %s can't be encoded", typ.Name())
		}
	}

	// if length != -1 && len(t[tag]) < length {
	// 	missing := length - len(t[tag])
	//
	// 	t[tag] = append(make([]byte, missing), t[tag]...)
	// }

	return nil
}

func (t Tlv) UnmarshalValue(tag int, value interface{}) (bool, error) {
	return t.UnmarshalValueWithOptions(tag, value, []string{})
}

func (t Tlv) UnmarshalValueWithOptions(tag int, value interface{}, options []string) (bool, error) {
	data, found := t[tag]

	if !found {
		return false, nil
	}

	reflectedValue := reflect.ValueOf(value)

	switch reflectedValue.Kind() {
	case reflect.Ptr, reflect.Interface:
		reflectedValue = reflectedValue.Elem()
	}

	if !reflectedValue.CanSet() {
		return true, fmt.Errorf("go type '%s' is read-only", reflectedValue.Type())
	}

	typ := reflectedValue.Type()

	decoder, ok := value.(TlvDecoder)

	if ok {
		return true, decoder.DecodeTlv(data)
	}

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
		case *[]byte:
			*v = data
		case *int:
			result, err := DecodeInteger(data)

			if err != nil {
				return true, err
			}

			*v = int(result)
		case *int64:
			result, err := DecodeInteger(data)

			if err != nil {
				return true, err
			}

			*v = result
		case *uint64:
			result, err := DecodeUInt(data)

			if err != nil {
				return true, err
			}

			*v = result
		case *uint:
			result, err := DecodeUInt(data)

			if err != nil {
				return true, err
			}

			*v = uint(result)
		case *string:
			if optsContains(options, "hex") {
				*v = hex.EncodeToString(data)
			} else {
				*v = string(data)
			}
		case *bool:
			result, err := DecodeUInt(data)

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

func (t Tlv) Bytes(tag int) ([]byte, bool, error) {
	result := []byte{}
	found, err := t.UnmarshalValue(tag, &result)

	if !found || err != nil {
		return nil, found, err
	}

	return result, true, nil
}

func DecodeTlv(data []byte) (Tlv, error) {
	tlv := make(Tlv)

	return tlv, tlv.DecodeTlv(data)
}

func optsContains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
