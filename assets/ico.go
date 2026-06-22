package assets

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"sort"
)

// EncodeICO packs one or more RGBA frames into a single multi-size Windows .ico
// file. Frames ≤ 64px are stored as classic BMP (BITMAPINFOHEADER + BGRA + AND
// mask); 256px frames are stored PNG-compressed, as Windows expects.
//
// A multi-size .ico lets Windows pick the best frame for each context (16px in
// the notification area at 100% DPI, 32px for the taskbar, larger for Explorer
// and high-DPI) instead of stretching one frame.
func EncodeICO(frames []*image.RGBA) []byte {
	// Sort ascending by width for a tidy, deterministic directory.
	sort.Slice(frames, func(i, j int) bool {
		return frames[i].Bounds().Dx() < frames[j].Bounds().Dx()
	})

	type encoded struct {
		w, h int
		data []byte
		png  bool
	}
	imgs := make([]encoded, 0, len(frames))
	for _, f := range frames {
		b := f.Bounds()
		w, h := b.Dx(), b.Dy()
		if w >= 256 {
			var buf bytes.Buffer
			_ = png.Encode(&buf, f)
			imgs = append(imgs, encoded{w, h, buf.Bytes(), true})
		} else {
			imgs = append(imgs, encoded{w, h, toICOResource(f), false})
		}
	}

	var buf bytes.Buffer
	// ICONDIR: reserved=0, type=1 (icon), count
	buf.Write([]byte{0, 0, 1, 0})
	binary.Write(&buf, binary.LittleEndian, uint16(len(imgs)))

	// Directory entries follow the header; image data follows all entries.
	offset := 6 + 16*len(imgs)
	for _, im := range imgs {
		entry := make([]byte, 16)
		entry[0] = byte(im.w) // 0 means 256
		entry[1] = byte(im.h)
		entry[2] = 0                                                   // palette colors (0 = ≥256)
		entry[3] = 0                                                   // reserved
		binary.LittleEndian.PutUint16(entry[4:], 1)                    // color planes
		binary.LittleEndian.PutUint16(entry[6:], 32)                   // bits per pixel
		binary.LittleEndian.PutUint32(entry[8:], uint32(len(im.data))) // bytes in resource
		binary.LittleEndian.PutUint32(entry[12:], uint32(offset))      // offset from file start
		buf.Write(entry)
		offset += len(im.data)
	}
	for _, im := range imgs {
		buf.Write(im.data)
	}
	return buf.Bytes()
}

// toICOResource encodes an *image.RGBA into the in-.ico BMP form used for frames
// up to 64px: BITMAPINFOHEADER + 32-bit BGRA XOR mask (bottom-up) + 1-bit AND
// mask. The AND mask is left all-zero; transparency comes from the BGRA alpha.
func toICOResource(img *image.RGBA) []byte {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()

	xorData := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		srcY := b.Min.Y + (h - 1 - y) // bottom-up rows
		for x := 0; x < w; x++ {
			c := img.RGBAAt(b.Min.X+x, srcY)
			i := (y*w + x) * 4
			xorData[i+0] = c.B
			xorData[i+1] = c.G
			xorData[i+2] = c.R
			xorData[i+3] = c.A
		}
	}

	// AND mask: 1 bit/pixel, rows padded to a DWORD boundary, all zero.
	andStride := ((w + 31) / 32) * 4
	andData := make([]byte, andStride*h)

	var buf bytes.Buffer
	var hdr [40]byte
	binary.LittleEndian.PutUint32(hdr[0:], 40)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(w))
	binary.LittleEndian.PutUint32(hdr[8:], uint32(h*2)) // XOR + AND stacked
	binary.LittleEndian.PutUint16(hdr[12:], 1)          // biPlanes
	binary.LittleEndian.PutUint16(hdr[14:], 32)         // biBitCount
	buf.Write(hdr[:])
	buf.Write(xorData)
	buf.Write(andData)
	return buf.Bytes()
}
