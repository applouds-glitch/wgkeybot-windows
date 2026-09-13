// Command genico regenerates the Windows application ICO and PNG from the
// procedural artwork in assets, and optionally writes an HTML preview gallery.
//
// Run from the repo root:
//
//	go run ./cmd/genico
//	go run ./cmd/genico -preview /tmp/wgkeybot-icons
//
// Then rebuild the embedded Windows resource:
//
//	GOARCH=amd64 goversioninfo -o rsrc_windows.syso versioninfo.json
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"os"
	"path/filepath"

	"github.com/wgkeybot/windows/assets"
)

func main() {
	out := flag.String("o", "assets/icon.ico", "output .ico path")
	pngOut := flag.String("png", "assets/icon.png", "output 512px .png path")
	preview := flag.String("preview", "", "if set, write a preview gallery to this directory")
	flag.Parse()

	ico := assets.BuildExeICO()
	mustWrite(*out, ico)
	mustWrite(*pngOut, assets.BuildExePNG())
	log.Printf("wrote %s (%d bytes) and %s", *out, len(ico), *pngOut)
	if *preview == "" {
		return
	}
	if err := os.MkdirAll(*preview, 0o755); err != nil {
		log.Fatal(err)
	}
	icons := []struct {
		Name  string
		Label string
		ICO   []byte
	}{
		{"app", "Приложение", ico},
		{"tray-connected", "Подключено", assets.IconConnected()},
		{"tray-connecting", "Подключение", assets.IconConnecting()},
		{"tray-connecting-dim", "Подключение · пульс", assets.IconConnectingDim()},
		{"tray-disconnected", "Отключено", assets.IconDisconnected()},
	}
	type row struct {
		Name  string
		Label string
		Sizes []int
	}
	var rows []row
	for _, icon := range icons {
		r := row{Name: icon.Name, Label: icon.Label}
		for _, frame := range icoFrames(icon.ICO) {
			size := frame.Bounds().Dx()
			writePNG(filepath.Join(*preview, fmt.Sprintf("%s-%d.png", icon.Name, size)), frame)
			r.Sizes = append(r.Sizes, size)
		}
		rows = append(rows, r)
	}
	mustWrite(filepath.Join(*preview, "app-512.png"), assets.BuildExePNG())
	var html bytes.Buffer
	if err := template.Must(template.New("gallery").Parse(gallery)).Execute(&html, rows); err != nil {
		log.Fatal(err)
	}
	mustWrite(filepath.Join(*preview, "index.html"), html.Bytes())
	// A compact contact sheet is also convenient to inspect without a browser.
	sheet := image.NewRGBA(image.Rect(0, 0, 720, 320))
	for row, bg := range []color.RGBA{{0xF3, 0xF6, 0xFA, 255}, {0x20, 0x24, 0x2B, 255}} {
		draw.Draw(sheet, image.Rect(0, row*160, 720, (row+1)*160), image.NewUniform(bg), image.Point{}, draw.Src)
		for col, icon := range icons {
			frames := icoFrames(icon.ICO)
			var large image.Image
			if col == 0 {
				large = frames[len(frames)-2]
			} else {
				large = frames[len(frames)-1]
			}
			b := large.Bounds()
			x, y := col*144+(144-b.Dx())/2, row*160+8+(128-b.Dy())/2
			draw.Draw(sheet, image.Rect(x, y, x+b.Dx(), y+b.Dy()), large, b.Min, draw.Over)
			small := frames[0]
			draw.Draw(sheet, image.Rect(col*144+64, row*160+140, col*144+80, row*160+156), small, small.Bounds().Min, draw.Over)
		}
	}
	writePNG(filepath.Join(*preview, "overview.png"), sheet)
	log.Printf("wrote previews to %s", *preview)
}

// Decode our generated ICO frames, including their straight-alpha BMP pixels.
func icoFrames(ico []byte) []image.Image {
	count := int(binary.LittleEndian.Uint16(ico[4:]))
	frames := make([]image.Image, 0, count)
	for i := 0; i < count; i++ {
		e := 6 + 16*i
		off := int(binary.LittleEndian.Uint32(ico[e+12:]))
		length := int(binary.LittleEndian.Uint32(ico[e+8:]))
		d := ico[off : off+length]
		if bytes.HasPrefix(d, []byte("\x89PNG")) {
			img, err := png.Decode(bytes.NewReader(d))
			if err != nil {
				log.Fatal(err)
			}
			frames = append(frames, img)
			continue
		}
		w := int(binary.LittleEndian.Uint32(d[4:]))
		h := int(binary.LittleEndian.Uint32(d[8:])) / 2
		img := image.NewNRGBA(image.Rect(0, 0, w, h))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				p := 40 + ((h-1-y)*w+x)*4
				img.SetNRGBA(x, y, color.NRGBA{R: d[p+2], G: d[p+1], B: d[p], A: d[p+3]})
			}
		}
		frames = append(frames, img)
	}
	return frames
}

func writePNG(path string, img image.Image) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		log.Fatal(err)
	}
	mustWrite(path, buf.Bytes())
}

func mustWrite(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatal(err)
	}
}

const gallery = `<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WgKeyBot · Windows icons</title>
<style>
*{box-sizing:border-box}body{margin:0;padding:40px;background:#e6ecf2;color:#10293d;font:15px system-ui,sans-serif}main{max-width:1080px;margin:auto}header{display:flex;align-items:center;gap:28px;margin-bottom:32px}header img{width:144px;height:144px}h1{font-size:32px;letter-spacing:-1px;margin:0 0 10px}p{color:#527087;line-height:1.6;margin:0}.themes{display:grid;grid-template-columns:1fr 1fr;gap:20px}section{padding:24px;border-radius:20px;background:#f3f6fa}section.dark{background:#20242b;color:#e5f4fa}h2{margin:0 0 20px;font-size:18px}.state{display:flex;gap:18px;align-items:center;min-height:86px;border-top:1px solid #8196ab30}.state>img{width:48px;height:48px}.label{width:150px;font-size:13px}.sizes{display:flex;align-items:center;gap:16px}.sizes img{display:block}.size{text-align:center;font-size:10px;color:#8293a2}.size span{display:block;margin-top:5px}.app{margin-top:20px;overflow:auto}.app .sizes{align-items:end;gap:24px}.app h2{margin-bottom:24px}@media(max-width:900px){.themes{grid-template-columns:1fr}body{padding:20px}}
</style><main><header><img src="app-512.png" alt="Новая иконка приложения"><div><h1>WgKeyBot для Windows</h1><p>Бот + ключ. Один характер во всех размерах.<br>Цвет и символ обозначают состояние соединения.</p></div></header>
<div class="themes"><section><h2>Светлая панель</h2>{{range .}}{{if ne .Name "app"}}<div class="state"><img src="{{.Name}}-48.png" alt=""><div class="label">{{.Label}}</div><div class="sizes"><div class="size"><img src="{{.Name}}-16.png" width="16" height="16" alt="{{.Label}}"><span>16</span></div><div class="size"><img src="{{.Name}}-20.png" width="20" height="20" alt=""><span>20</span></div><div class="size"><img src="{{.Name}}-24.png" width="24" height="24" alt=""><span>24</span></div><div class="size"><img src="{{.Name}}-32.png" width="32" height="32" alt=""><span>32</span></div></div></div>{{end}}{{end}}</section>
<section class="dark"><h2>Тёмная панель</h2>{{range .}}{{if ne .Name "app"}}<div class="state"><img src="{{.Name}}-48.png" alt=""><div class="label">{{.Label}}</div><div class="sizes"><div class="size"><img src="{{.Name}}-16.png" width="16" height="16" alt="{{.Label}}"><span>16</span></div><div class="size"><img src="{{.Name}}-20.png" width="20" height="20" alt=""><span>20</span></div><div class="size"><img src="{{.Name}}-24.png" width="24" height="24" alt=""><span>24</span></div><div class="size"><img src="{{.Name}}-32.png" width="32" height="32" alt=""><span>32</span></div></div></div>{{end}}{{end}}</section></div>
<section class="app"><h2>Проводник · панель задач · ярлыки</h2><div class="sizes">{{range .}}{{if eq .Name "app"}}{{range .Sizes}}<div class="size"><img src="app-{{.}}.png" width="{{.}}" height="{{.}}" alt="Иконка {{.}} px"><span>{{.}} px</span></div>{{end}}{{end}}{{end}}</div></section></main></html>`
