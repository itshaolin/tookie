// Package tookie provides
// ...
package tookie

import (
    "testing"
    "github.com/itshaolin/goblin"
)

func TestTools(t *testing.T) {
    g := goblin.Goblin(t)

    g.Describe("#consumeFieldV2", func() {

        g.It("extracts one", func() {
            v, r := consumeFieldV2("4:asdf|...")
            g.Assert(v).Equal("asdf")
            g.Assert(r).Equal("...")
        })

        g.It("no rest error", func() {
            defer g.AssertPanic()
            consumeFieldV2("3:zxc")
        })

        g.It("malformed field error", func() {
            defer g.AssertPanic()
            consumeFieldV2("5:zxc|Tail")
        })
    })
}

func TestDecode(t *testing.T) {
    g := goblin.Goblin(t)

    g.Describe("#decodeFields", func() {
        //skey := "secure_key"
        //
        //    g.It("decodes Tornado v.2 secured cookie", func() {
        //        enc := "2|1:0|10:1474429838|4:some|8:dmFsdWU=|bf3d274f65723ddb8ce27c74b1c5fa76def0bffa27b583f2887bf6c7e9fc4016"
        //        ver, name, dec := decodeFields(enc)
        //        g.Assert(dec).Equal("value")
        //    })
        //
        g.It("decodes Tornado v.2 secured cookie #2", func() {
            enc := "2|1:0|10:1474488231|1:2|8:U2Vjb25k|accec3cbe6fea20fb48cafafe2e77c459ca31b9ae7d83b6f4f6c93e26fa4d85b"
            c, err := decodeFieldsV2(enc)
            g.Assert(err).Equal(nil)
            g.Assert(c.Sig).Equal("accec3cbe6fea20fb48cafafe2e77c459ca31b9ae7d83b6f4f6c93e26fa4d85b")
            g.Assert(c.Version).Equal(0)
            g.Assert(c.Name).Equal("2")
            g.Assert(c.Value).Equal("U2Vjb25k")
        })

    })
}

func TestTookie(t *testing.T) {
    t.Skip()
    g := goblin.Goblin(t)

    g.Describe("#Decode", func() {
        skey := "secure_key"

        g.It("decodes Tornado v.2 secured cookie", func() {
            enc := "2|1:0|10:1474429838|4:some|8:dmFsdWU=|bf3d274f65723ddb8ce27c74b1c5fa76def0bffa27b583f2887bf6c7e9fc4016"
            dec := Decode(skey, "some", enc)
            g.Assert(dec).Equal("value")
        })

        g.It("decodes Tornado v.2 secured cookie #2", func() {
            enc := "2|1:0|10:1474488231|1:2|8:U2Vjb25k|accec3cbe6fea20fb48cafafe2e77c459ca31b9ae7d83b6f4f6c93e26fa4d85b"
            dec := Decode(skey, "2", enc)
            g.Assert(dec).Equal("Second")
        })

    })

}
