package assets

import (
	"image"
	"image/color"
	"math"
)

// Artwork uses a 16-unit grid. Every output size is rasterised directly.
var (
	ink   = color.RGBA{0x10, 0x29, 0x3D, 0xFF}
	aqua  = color.RGBA{0x58, 0xEB, 0xD5, 0xFF}
	green = color.RGBA{0x55, 0xE0, 0xAC, 0xFF}
	amber = color.RGBA{0xFF, 0xCD, 0x66, 0xFF}
	slate = color.RGBA{0xB9, 0xC7, 0xD5, 0xFF}
)

type trayState uint8

const (
	disconnected trayState = iota
	connecting
	connected
)

// Include both notification-area and LoadImage/LR_DEFAULTSIZE frame sizes.
var traySizes = []int{16, 20, 24, 32, 40, 48, 64}

func trayICO(state trayState, dim bool) []byte {
	frames := make([]*image.RGBA, 0, len(traySizes))
	for _, size := range traySizes {
		frames = append(frames, renderTray(size, state, dim))
	}
	return EncodeICO(frames)
}

func renderTray(size int, state trayState, dim bool) *image.RGBA {
	accent := slate
	if state == connected {
		accent = green
	} else if state == connecting {
		accent = amber
		if dim {
			accent = color.RGBA{0xD9, 0xA2, 0x43, 0xFF}
		}
	}
	return rasterise(size, func(x, y float64) color.RGBA {
		var c color.RGBA
		// A pale silhouette with a dark rim stays visible on both taskbar themes.
		if botBody(x, y, 0.65) {
			c = ink
		}
		if botBody(x, y, 0) {
			c = color.RGBA{0xE5, 0xF4, 0xFA, 0xFF}
		}
		if roundedRect(x, y, 3.1, 5.4, 12.6, 11.2, 1.9) {
			c = ink
		}
		eyeBottom := 9.1
		if state == disconnected {
			eyeBottom = 8.2
		}
		if roundedRect(x, y, 4.8, 7, 6.3, eyeBottom, 0.65) ||
			roundedRect(x, y, 9.3, 7, 10.8, eyeBottom, 0.65) {
			c = accent
		}
		// The badge encodes state by shape as well as colour: check, dots, minus.
		if circle(x, y, 12, 12, 3.9) {
			c = ink
		}
		if circle(x, y, 12, 12, 3.15) {
			c = accent
		}
		var symbol bool
		switch state {
		case connected:
			symbol = stroke(x, y, 10.4, 12, 11.5, 13.1, 0.65) ||
				stroke(x, y, 11.5, 13.1, 13.6, 10.8, 0.65)
		case connecting:
			symbol = circle(x, y, 10.6, 12, 0.7) || circle(x, y, 13.4, 12, 0.7)
		default:
			symbol = roundedRect(x, y, 10.3, 11.4, 13.7, 12.6, 0.5)
		}
		if symbol {
			c = ink
		}
		return c
	})
}

func botBody(x, y, grow float64) bool {
	return roundedRect(x, y, 1.9-grow, 3.8-grow, 13.8+grow, 12.7+grow, 2.7+grow) ||
		roundedRect(x, y, 0.7-grow, 6.7-grow, 2.8+grow, 10.1+grow, 0.85+grow) ||
		roundedRect(x, y, 12.9-grow, 6.7-grow, 15+grow, 10.1+grow, 0.85+grow) ||
		roundedRect(x, y, 7.3-grow, 2-grow, 8.4+grow, 4.3+grow, 0.5+grow) ||
		circle(x, y, 7.85, 1.8, 1+grow)
}

func roundedRect(x, y, x0, y0, x1, y1, r float64) bool {
	r = math.Min(r, math.Min((x1-x0)/2, (y1-y0)/2))
	dx := math.Max(math.Max(x0+r-x, x-(x1-r)), 0)
	dy := math.Max(math.Max(y0+r-y, y-(y1-r)), 0)
	return dx*dx+dy*dy <= r*r
}

func circle(x, y, cx, cy, r float64) bool {
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= r*r
}

func stroke(x, y, x0, y0, x1, y1, radius float64) bool {
	dx, dy := x1-x0, y1-y0
	t := math.Max(0, math.Min(1, ((x-x0)*dx+(y-y0)*dy)/(dx*dx+dy*dy)))
	return circle(x, y, x0+t*dx, y0+t*dy, radius)
}

func blend(a, b color.RGBA, t float64) color.RGBA {
	t = math.Max(0, math.Min(1, t))
	return color.RGBA{
		R: uint8(float64(a.R)*(1-t) + float64(b.R)*t),
		G: uint8(float64(a.G)*(1-t) + float64(b.G)*t),
		B: uint8(float64(a.B)*(1-t) + float64(b.B)*t),
		A: 255,
	}
}

// Samples are opaque or transparent. Averaging all four channels produces
// premultiplied RGBA, including colour at partially covered edges.
func rasterise(size int, sample func(x, y float64) color.RGBA) *image.RGBA {
	const ss = 4
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a uint32
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/ss) * 16 / float64(size)
					py := (float64(y) + (float64(sy)+0.5)/ss) * 16 / float64(size)
					c := sample(px, py)
					r += uint32(c.R)
					g += uint32(c.G)
					b += uint32(c.B)
					a += uint32(c.A)
				}
			}
			dst.SetRGBA(x, y, color.RGBA{uint8(r / (ss * ss)), uint8(g / (ss * ss)), uint8(b / (ss * ss)), uint8(a / (ss * ss))})
		}
	}
	return dst
}
