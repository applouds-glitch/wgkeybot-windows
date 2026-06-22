// Command genico regenerates assets/icon.ico (the .exe application icon) from
// assets/icon.png, and can dump PNG previews of the generated tray and exe
// icons for visual inspection.
//
// Run from the repo root:
//
//	go run ./cmd/genico                 # regenerate assets/icon.ico
//	go run ./cmd/genico -preview out    # also write PNG previews to ./out
//
// After regenerating icon.ico, rebuild the .syso so the new icon is embedded:
//
//	goversioninfo -o rsrc_windows.syso versioninfo.json
package main

import (
	"bytes"
	"flag"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
	"path/filepath"

	"github.com/wgkeybot/windows/assets"
)

func main() {
	out := flag.String("o", "assets/icon.ico", "output .ico path")
	preview := flag.String("preview", "", "if set, write PNG previews to this directory")
	flag.Parse()

	ico := assets.BuildExeICO()
	if err := os.WriteFile(*out, ico, 0o644); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}
	log.Printf("wrote %s (%d bytes)", *out, len(ico))

	if *preview == "" {
		return
	}
	if err := os.MkdirAll(*preview, 0o755); err != nil {
		log.Fatal(err)
	}
	// Tray states blown up 12× (nearest-neighbour) so individual pixels are
	// visible, on a checkerboard so transparency is obvious.
	previews := map[string][]byte{
		"tray-connected":    assets.IconConnected(),
		"tray-connecting":   assets.IconConnecting(),
		"tray-disconnected": assets.IconDisconnected(),
	}
	for name, icoBytes := range previews {
		img := firstICOFrame(icoBytes) // smallest frame = 16px
		path := filepath.Join(*preview, name+"-16x12.png")
		writePNG(path, zoomOnChecker(img, 12))
	}
	log.Printf("wrote previews to %s", *preview)
}

// firstICOFrame decodes the smallest BMP frame out of an .ico we generated.
// Our frames are 32-bit BGRA with a doubled-height BITMAPINFOHEADER.
func firstICOFrame(ico []byte) *image.RGBA {
	count := int(ico[4]) | int(ico[5])<<8
	// Pick the entry with the smallest width (byte 0; 0 means 256).
	bestOff, bestW := 0, 1<<30
	for i := 0; i < count; i++ {
		e := 6 + 16*i
		w := int(ico[e])
		if w == 0 {
			w = 256
		}
		off := int(ico[e+12]) | int(ico[e+13])<<8 | int(ico[e+14])<<16 | int(ico[e+15])<<24
		if w < bestW {
			bestW, bestOff = w, off
		}
	}
	return decodeBMPFrame(ico[bestOff:])
}

func decodeBMPFrame(d []byte) *image.RGBA {
	w := int(d[4]) | int(d[5])<<8 | int(d[6])<<16 | int(d[7])<<24
	h2 := int(d[8]) | int(d[9])<<8 | int(d[10])<<16 | int(d[11])<<24
	h := h2 / 2
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	px := d[40:]
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := ((h-1-y)*w + x) * 4 // stored bottom-up
			img.SetRGBA(x, y, color.RGBA{R: px[i+2], G: px[i+1], B: px[i+0], A: px[i+3]})
		}
	}
	return img
}

func zoomOnChecker(src *image.RGBA, z int) *image.RGBA {
	b := src.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, b.Dx()*z, b.Dy()*z))
	light := color.RGBA{0xCC, 0xCC, 0xCC, 0xFF}
	dark := color.RGBA{0x99, 0x99, 0x99, 0xFF}
	for y := 0; y < dst.Bounds().Dy(); y++ {
		for x := 0; x < dst.Bounds().Dx(); x++ {
			bg := light
			if (x/8+y/8)%2 == 0 {
				bg = dark
			}
			fg := src.RGBAAt(x/z, y/z)
			dst.SetRGBA(x, y, over(fg, bg))
		}
	}
	return dst
}

// over alpha-composites fg onto an opaque bg.
func over(fg, bg color.RGBA) color.RGBA {
	a := float64(fg.A) / 255
	return color.RGBA{
		R: uint8(float64(fg.R)*a + float64(bg.R)*(1-a)),
		G: uint8(float64(fg.G)*a + float64(bg.G)*(1-a)),
		B: uint8(float64(fg.B)*a + float64(bg.B)*(1-a)),
		A: 0xFF,
	}
}

func writePNG(path string, img image.Image) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}
