package assets

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
)

//go:embed icon.png
var iconPNG []byte

// IconConnected returns the app icon in full color (32×32, Windows icon resource format).
func IconConnected() []byte { return makeIcon(mustDecode(iconPNG), 32, false, false) }

// IconDisconnected returns the app icon converted to grayscale.
func IconDisconnected() []byte { return makeIcon(mustDecode(iconPNG), 32, true, false) }

// IconConnecting returns the app icon with a yellow tint.
func IconConnecting() []byte { return makeIcon(mustDecode(iconPNG), 32, false, true) }

func makeIcon(src image.Image, size int, grayscale, yellowTint bool) []byte {
	// Crop to robot head (top-center region) before scaling so the face
	// is recognisable at 32×32 tray size.
	cropped := cropFraction(src, 0.20, 0.02, 0.80, 0.58)
	scaled := scaleBox(cropped, size, size)
	var img *image.RGBA
	switch {
	case grayscale:
		img = toGrayscale(scaled)
	case yellowTint:
		img = toYellowTint(scaled)
	default:
		img = scaled
	}
	return toICOFile(img)
}

// cropFraction returns the sub-image defined by fractional coordinates
// (x0f, y0f) – (x1f, y1f) relative to src bounds.
func cropFraction(src image.Image, x0f, y0f, x1f, y1f float64) image.Image {
	b := src.Bounds()
	w := float64(b.Dx())
	h := float64(b.Dy())
	x0 := b.Min.X + int(x0f*w)
	y0 := b.Min.Y + int(y0f*h)
	x1 := b.Min.X + int(x1f*w)
	y1 := b.Min.Y + int(y1f*h)
	type subImager interface {
		SubImage(r image.Rectangle) image.Image
	}
	if si, ok := src.(subImager); ok {
		return si.SubImage(image.Rect(x0, y0, x1, y1))
	}
	// Fallback: copy pixels manually
	dst := image.NewRGBA(image.Rect(0, 0, x1-x0, y1-y0))
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			dst.Set(x-x0, y-y0, src.At(x, y))
		}
	}
	return dst
}

// toICOFile wraps toICOResource in a valid .ico file (ICONDIR + ICONDIRENTRY +
// image data). systray v1.2.2 writes bytes to a temp .ico and loads via
// LoadImageW, so it requires a proper .ico file, not raw resource bits.
func toICOFile(img *image.RGBA) []byte {
	imgData := toICOResource(img)
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	// ICO spec: width/height byte = 0 means 256; 32 fits in a byte directly.
	var buf bytes.Buffer
	// ICONDIR header (6 bytes)
	buf.Write([]byte{0, 0, 1, 0, 1, 0}) // reserved=0, type=1 (icon), count=1
	// ICONDIRENTRY (16 bytes)
	entry := make([]byte, 16)
	entry[0] = byte(w)
	entry[1] = byte(h)
	entry[2] = 0 // color count (0 = ≥256 colors)
	entry[3] = 0 // reserved
	binary.LittleEndian.PutUint16(entry[4:], 1)                     // planes
	binary.LittleEndian.PutUint16(entry[6:], 32)                    // bit count
	binary.LittleEndian.PutUint32(entry[8:], uint32(len(imgData)))  // image size
	binary.LittleEndian.PutUint32(entry[12:], 6+16)                 // offset = header + 1 entry
	buf.Write(entry)
	buf.Write(imgData)
	return buf.Bytes()
}

// toICOResource encodes *image.RGBA into the binary format expected by
// CreateIconFromResourceEx: BITMAPINFOHEADER + BGRA XOR mask + 1-bit AND mask.
// This is the "icon resource bits" format, not a standalone .ico file.
func toICOResource(img *image.RGBA) []byte {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()

	// XOR mask: 32-bit BGRA, bottom-up row order
	xorData := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		srcY := b.Min.Y + (h - 1 - y) // flip vertically
		for x := 0; x < w; x++ {
			c := img.RGBAAt(b.Min.X+x, srcY)
			i := (y*w + x) * 4
			xorData[i+0] = c.B
			xorData[i+1] = c.G
			xorData[i+2] = c.R
			xorData[i+3] = c.A
		}
	}

	// AND mask: 1 bit per pixel, rows padded to DWORD boundary, all 0 (use XOR alpha)
	andStride := ((w + 31) / 32) * 4
	andData := make([]byte, andStride*h)

	var buf bytes.Buffer

	// BITMAPINFOHEADER (40 bytes)
	var hdr [40]byte
	binary.LittleEndian.PutUint32(hdr[0:], 40)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(w))
	binary.LittleEndian.PutUint32(hdr[8:], uint32(h*2)) // height doubled: XOR + AND stacked
	binary.LittleEndian.PutUint16(hdr[12:], 1)          // biPlanes
	binary.LittleEndian.PutUint16(hdr[14:], 32)         // biBitCount
	// biCompression, biSizeImage, etc. all zero = BI_RGB

	buf.Write(hdr[:])
	buf.Write(xorData)
	buf.Write(andData)
	return buf.Bytes()
}

// --- image helpers ---

func mustDecode(data []byte) image.Image {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		panic("assets: invalid icon.png: " + err.Error())
	}
	return img
}

// scaleBox downscales src to w×h using a box (averaging) filter.
func scaleBox(src image.Image, w, h int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	sb := src.Bounds()
	scaleX := float64(sb.Dx()) / float64(w)
	scaleY := float64(sb.Dy()) / float64(h)

	for dy := 0; dy < h; dy++ {
		for dx := 0; dx < w; dx++ {
			x0 := int(float64(dx) * scaleX)
			y0 := int(float64(dy) * scaleY)
			x1 := int(float64(dx+1)*scaleX) + 1
			y1 := int(float64(dy+1)*scaleY) + 1
			if x1 > sb.Dx() {
				x1 = sb.Dx()
			}
			if y1 > sb.Dy() {
				y1 = sb.Dy()
			}

			var rS, gS, bS, aS, n float64
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					r, g, bl, a := src.At(sb.Min.X+sx, sb.Min.Y+sy).RGBA()
					rS += float64(r >> 8)
					gS += float64(g >> 8)
					bS += float64(bl >> 8)
					aS += float64(a >> 8)
					n++
				}
			}
			if n > 0 {
				dst.SetRGBA(dx, dy, color.RGBA{
					R: uint8(rS / n),
					G: uint8(gS / n),
					B: uint8(bS / n),
					A: uint8(aS / n),
				})
			}
		}
	}
	return dst
}

// toGrayscale converts to grayscale preserving alpha.
func toGrayscale(src *image.RGBA) *image.RGBA {
	b := src.Bounds()
	dst := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := src.RGBAAt(x, y)
			// ITU-R BT.601 luminance (integer approximation)
			lum := (19595*uint32(c.R) + 38470*uint32(c.G) + 7471*uint32(c.B) + 1<<15) >> 16
			dst.SetRGBA(x, y, color.RGBA{uint8(lum), uint8(lum), uint8(lum), c.A})
		}
	}
	return dst
}

// toYellowTint zeros the blue channel to give a warm yellow hue.
func toYellowTint(src *image.RGBA) *image.RGBA {
	b := src.Bounds()
	dst := image.NewRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := src.RGBAAt(x, y)
			dst.SetRGBA(x, y, color.RGBA{c.R, c.G, 0, c.A})
		}
	}
	return dst
}
