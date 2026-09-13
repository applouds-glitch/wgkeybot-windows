package assets

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"sync"
)

// Cache each state once; the connection pulse must not rasterise and encode
// seven ICO frames on every timer tick.
var (
	connectedIcon    = sync.OnceValue(func() []byte { return trayICO(connected, false) })
	disconnectedIcon = sync.OnceValue(func() []byte { return trayICO(disconnected, false) })
	connectingIcon   = sync.OnceValue(func() []byte { return trayICO(connecting, false) })
	connectingDim    = sync.OnceValue(func() []byte { return trayICO(connecting, true) })
)

// IconConnected returns the bot with a mint check badge.
func IconConnected() []byte { return connectedIcon() }

// IconDisconnected returns the bot with a gray minus badge.
func IconDisconnected() []byte { return disconnectedIcon() }

// IconConnecting returns the bot with an amber progress badge.
func IconConnecting() []byte { return connectingIcon() }

// IconConnectingDim is the second amber pulse frame, retaining the progress
// symbol so connecting never briefly looks like a disconnected state.
func IconConnectingDim() []byte { return connectingDim() }

var exeSizes = []int{16, 20, 24, 32, 40, 48, 64, 128, 256}

// BuildExeICO renders the application artwork independently at each size.
func BuildExeICO() []byte {
	frames := make([]*image.RGBA, 0, len(exeSizes))
	for _, size := range exeSizes {
		frames = append(frames, renderApp(size))
	}
	return EncodeICO(frames)
}

// BuildExePNG returns the 512px master preview of the same procedural artwork.
func BuildExePNG() []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, renderApp(512)); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func renderApp(size int) *image.RGBA {
	return rasterise(size, func(x, y float64) color.RGBA {
		if !roundedRect(x, y, 0.6, 0.6, 15.4, 15.4, 3.5) {
			return color.RGBA{}
		}
		c := blend(color.RGBA{0x20, 0x50, 0x6A, 255}, ink, (x+y)/26)
		if !roundedRect(x, y, 0.75, 0.75, 15.25, 15.25, 3.35) {
			return blend(c, color.RGBA{0x61, 0xA3, 0xB4, 255}, 0.35)
		}
		// Shared bot silhouette, inset to leave breathing room inside the tile.
		bx, by := (x-1.8)/0.78, (y-1.5)/0.78
		if botBody(bx, by-0.45, 0.2) {
			c = color.RGBA{0x0B, 0x20, 0x33, 255}
		}
		if botBody(bx, by, 0) {
			c = blend(color.RGBA{0xA5, 0xFF, 0xE9, 255}, color.RGBA{0x1B, 0xB6, 0xBC, 255}, (by-2)/13)
		}
		if roundedRect(bx, by, 3, 5.15, 12.7, 11.15, 2) {
			c = ink
		}
		if roundedRect(bx, by, 3.3, 5.45, 12.4, 10.85, 1.75) {
			c = blend(color.RGBA{0x1E, 0x4B, 0x62, 255}, ink, (by-5)/6)
		}
		if roundedRect(bx, by, 4.8, 6.8, 6.3, 9, 0.75) ||
			roundedRect(bx, by, 9.3, 6.8, 10.8, 9, 0.75) {
			c = aqua
		}
		// A small smile is omitted in the smallest frames.
		if size >= 32 && stroke(bx, by, 7.1, 9.8, 8.5, 9.8, 0.3) {
			c = aqua
		}
		// Golden key overlaps the bottom-right rim. The generous tooth remains
		// readable at 16px; there is no miniature lettering.
		if appKey(x, y, 0.32) {
			c = ink
		}
		if appKey(x, y, 0) {
			c = blend(color.RGBA{0xFF, 0xE8, 0x9D, 255}, color.RGBA{0xF8, 0xB5, 0x47, 255}, (y-9)/5)
		}
		if circle(x, y, 9.7, 10.7, 0.62) {
			c = ink
		}
		return c
	})
}

func appKey(x, y, grow float64) bool {
	return circle(x, y, 9.7, 10.7, 1.55+grow) ||
		stroke(x, y, 10.6, 11.6, 12.8, 13.8, 0.57+grow) ||
		stroke(x, y, 12.1, 13.1, 13, 12.2, 0.5+grow)
}
