package assets

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestICOTransparency(t *testing.T) {
	// A partially covered coloured edge and a transparent pixel on opposite
	// rows exercise straight alpha, bottom-up storage and DWORD mask padding.
	frame := image.NewRGBA(image.Rect(0, 0, 33, 2))
	frame.SetRGBA(0, 0, color.RGBA{32, 64, 96, 128})
	frame.SetRGBA(32, 1, color.RGBA{255, 255, 255, 255})
	ico := EncodeICO([]*image.RGBA{frame})
	offset := int(binary.LittleEndian.Uint32(ico[18:]))
	data := ico[offset:]
	edge := data[40+33*4 : 40+33*4+4]
	if !bytes.Equal(edge, []byte{191, 127, 63, 128}) {
		t.Fatalf("DIB edge = %v; want straight-alpha BGRA [191 127 63 128]", edge)
	}
	mask := data[40+33*2*4:]
	if len(mask) != 16 {
		t.Fatalf("AND mask length = %d; want two DWORD-padded 8-byte rows", len(mask))
	}
	if mask[0]&0x80 == 0 || mask[4]&0x80 != 0 || mask[8]&0x80 != 0 || mask[12]&0x80 == 0 {
		t.Fatalf("incorrect bottom-up transparency mask: %x", mask)
	}
}

func TestICOMixedBMPAndPNG(t *testing.T) {
	small := image.NewRGBA(image.Rect(0, 0, 16, 16))
	large := image.NewRGBA(image.Rect(0, 0, 256, 256))
	large.SetRGBA(100, 100, color.RGBA{32, 64, 96, 128})
	ico := EncodeICO([]*image.RGBA{large, small})
	if !bytes.Equal(ico[:6], []byte{0, 0, 1, 0, 2, 0}) {
		t.Fatalf("invalid ICONDIR: %v", ico[:6])
	}
	next := 6 + 2*16
	for i, size := range []int{16, 256} {
		entry := ico[6+i*16 : 6+(i+1)*16]
		if entry[0] != byte(size%256) || entry[1] != byte(size%256) {
			t.Fatalf("frame %d has incorrect dimensions", i)
		}
		offset := int(binary.LittleEndian.Uint32(entry[12:]))
		length := int(binary.LittleEndian.Uint32(entry[8:]))
		if offset != next || offset+length > len(ico) {
			t.Fatalf("frame %d has invalid offset/length", i)
		}
		next = offset + length
		if size == 256 {
			img, err := png.Decode(bytes.NewReader(ico[offset:next]))
			if err != nil {
				t.Fatal(err)
			}
			if img.Bounds() != large.Bounds() {
				t.Fatalf("PNG bounds = %v", img.Bounds())
			}
			got := color.NRGBAModel.Convert(img.At(100, 100)).(color.NRGBA)
			if got.A != 128 || got.R < 63 || got.G < 127 || got.B < 191 {
				t.Fatalf("PNG lost edge colour/alpha: %v", got)
			}
		}
	}
	if next != len(ico) {
		t.Fatal("unreferenced data after the last frame")
	}
}
