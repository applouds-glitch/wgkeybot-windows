package assets

import (
	"image"
	"image/color"
	"math"
)

// Tray icon palette. Bright fills read on a dark taskbar; a near-black outline
// keeps the silhouette legible on a light (Windows 11) taskbar.
var (
	keyGreen   = color.RGBA{0x34, 0xC7, 0x59, 0xFF} // connected
	keyAmber   = color.RGBA{0xFF, 0xB0, 0x00, 0xFF} // connecting
	keyGray    = color.RGBA{0x9A, 0xA0, 0xA6, 0xFF} // disconnected
	keyOutline = color.RGBA{0x18, 0x1C, 0x2B, 0xFF}
)

// Sizes packed into each tray .ico. getlantern/systray loads the icon with
// LoadImage + LR_DEFAULTSIZE, i.e. it picks the SM_CXICON frame — 32px at 100%
// DPI, 40/48/64 at 125/150/200%. We include those so high-DPI never stretches,
// plus the smaller frames the shell renders in the notification area itself.
var traySizes = []int{16, 20, 24, 32, 40, 48, 64}

// keyICO renders the key glyph at every tray size with the given fill and packs
// them into one multi-size .ico.
func keyICO(fill color.RGBA) []byte {
	frames := make([]*image.RGBA, 0, len(traySizes))
	for _, s := range traySizes {
		frames = append(frames, renderKey(s, fill, keyOutline))
	}
	return EncodeICO(frames)
}

// renderKey draws a key silhouette (round bow + shaft + two teeth) at size×size
// with an outline halo. It rasterises at 4× and box-downsamples for clean
// anti-aliased edges without any external rasteriser.
func renderKey(size int, fill, outline color.RGBA) *image.RGBA {
	const ss = 4 // supersampling factor
	big := size * ss

	// Outline thickness, in normalised units. Scaled up a touch at tiny sizes so
	// the halo never collapses to nothing after downsampling.
	out := 0.05
	if size <= 16 {
		out = 0.06
	}

	// Tilt the key ~30° so it fills the square better (bigger features at tiny
	// sizes) while keeping the teeth horizontal enough to stay separated. We
	// rotate the *sample* point about the centre, which rotates the shape the
	// opposite way.
	const sin, cos = 0.5, 0.8660254

	acc := image.NewRGBA(image.Rect(0, 0, big, big))
	for py := 0; py < big; py++ {
		for px := 0; px < big; px++ {
			// Normalised coords at the pixel centre, then un-rotate about (0.5,0.5).
			nx := (float64(px)+0.5)/float64(big) - 0.5
			ny := (float64(py)+0.5)/float64(big) - 0.5
			x := cos*nx + sin*ny + 0.5
			y := -sin*nx + cos*ny + 0.5
			switch {
			case keyInside(x, y, 0):
				acc.SetRGBA(px, py, fill)
			case keyInside(x, y, out):
				acc.SetRGBA(px, py, outline)
			}
		}
	}
	return downsample(acc, ss)
}

// keyInside reports whether (x,y) in [0,1]² is inside the key shape grown
// outward by g (g=0 is the glyph itself; g>0 yields the outline envelope).
func keyInside(x, y, g float64) bool {
	// Round bow (annulus) on the left.
	const bx, by = 0.30, 0.50
	const rOuter, rInner = 0.205, 0.085
	dx, dy := x-bx, y-by
	dist := math.Hypot(dx, dy)
	if dist <= rOuter+g && dist >= rInner-g {
		return true
	}

	// Shaft: a horizontal bar from the bow to the toothed end.
	if inRect(x, y, 0.30, 0.455, 0.88, 0.545, g) {
		return true
	}
	// Two teeth hanging off the shaft's far end.
	if inRect(x, y, 0.625, 0.545, 0.695, 0.66, g) {
		return true
	}
	if inRect(x, y, 0.79, 0.545, 0.86, 0.70, g) {
		return true
	}
	return false
}

// inRect reports whether (x,y) is within [x0,x1]×[y0,y1] expanded by g on each side.
func inRect(x, y, x0, y0, x1, y1, g float64) bool {
	return x >= x0-g && x <= x1+g && y >= y0-g && y <= y1+g
}

// downsample averages ss×ss blocks of src into a size×size RGBA, premultiplying
// by coverage so anti-aliased edges fade correctly against transparency.
func downsample(src *image.RGBA, ss int) *image.RGBA {
	size := src.Bounds().Dx() / ss
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	n := float64(ss * ss)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					c := src.RGBAAt(x*ss+sx, y*ss+sy)
					af := float64(c.A) / 255
					// Weight colour by alpha so transparent samples don't darken edges.
					r += float64(c.R) * af
					g += float64(c.G) * af
					b += float64(c.B) * af
					a += float64(c.A)
				}
			}
			if a == 0 {
				continue
			}
			aw := a / 255 // summed coverage
			dst.SetRGBA(x, y, color.RGBA{
				R: uint8(r/aw + 0.5),
				G: uint8(g/aw + 0.5),
				B: uint8(b/aw + 0.5),
				A: uint8(a/n + 0.5),
			})
		}
	}
	return dst
}
