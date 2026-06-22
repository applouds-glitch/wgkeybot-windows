package assets

import (
	"bytes"
	_ "embed"
	"image"
	"image/color"
	"image/png"
)

//go:embed icon.png
var iconPNG []byte

// --- Tray icons -------------------------------------------------------------
//
// The tray shows a simple, high-contrast key glyph rather than a shrunk-down
// copy of the detailed app artwork: at 16px the robot illustration turns to
// mush, whereas the key silhouette stays legible. Each state is a full
// multi-size .ico so Windows never has to stretch a frame.

// IconConnected returns the green "connected" tray icon.
func IconConnected() []byte { return keyICO(keyGreen) }

// IconDisconnected returns the gray "disconnected" tray icon.
func IconDisconnected() []byte { return keyICO(keyGray) }

// IconConnecting returns the amber "connecting" tray icon.
func IconConnecting() []byte { return keyICO(keyAmber) }

// --- Executable icon --------------------------------------------------------

// exeSizes are the frames packed into the .exe's icon.ico. Windows uses 16px in
// the title bar / small taskbar, 32px in the taskbar, 48px in Explorer's medium
// view and 256px for large/extra-large views; the in-between sizes keep things
// crisp across DPI scales.
var exeSizes = []int{16, 20, 24, 32, 40, 48, 64, 256}

// BuildExeICO regenerates the multi-size application icon from icon.png (the
// full robot artwork). It is driven offline by cmd/genico, which writes the
// result to assets/icon.ico for goversioninfo to embed via the .syso.
func BuildExeICO() []byte {
	src := mustDecode(iconPNG)
	frames := make([]*image.RGBA, 0, len(exeSizes))
	for _, s := range exeSizes {
		frames = append(frames, scaleBox(src, s, s))
	}
	return EncodeICO(frames)
}

// --- helpers ----------------------------------------------------------------

func mustDecode(data []byte) image.Image {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		panic("assets: invalid icon.png: " + err.Error())
	}
	return img
}

// scaleBox downscales src to w×h using a box (area-averaging) filter, a good
// quality choice for shrinking a detailed source.
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
