// Package tookie provides
// - encoding/decoding of Tornado webserver secure cookies
// - supports version 2 only
package tookie

import (
    "fmt"
    "strings"
    "strconv"
    "errors"
)

func Decode(secretKey, name, enc string) string {
    return "value"
}

type Cookie struct {
    Version int
    Name string
    Value string
    Sig string
}

func consumeFieldV2(rest string) (v string, r string) {
    arr := strings.SplitN(rest, ":", 2)
    ln, err := strconv.Atoi(arr[0])
    if err != nil {
        panic(err)
    }
    rest = arr[1]
    v = rest[:ln]
    if rest[ln] != '|' {
        panic(fmt.Sprintf("malformed v2 signed value field: %s", rest))
    }
    return v, rest[ln + 1:]
}

func decodeFieldsV2(s string) (c *Cookie, err error) {
    c = new(Cookie)

    defer func(c *Cookie) (*Cookie, error) {
        if err := recover(); err != nil {
            return nil, errors.New("malformed v2 signed value field")
        }
        return c, nil
    }(c)

    version, rest := consumeFieldV2(s[2:])
    c.Version, err = strconv.Atoi(version)
    if err != nil {
        return nil, err
    }
    _, rest = consumeFieldV2(rest)
    c.Name, rest = consumeFieldV2(rest)
    c.Value, c.Sig = consumeFieldV2(rest)
    return
}
