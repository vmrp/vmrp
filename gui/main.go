package main

/*
#cgo windows CFLAGS: -Wno-pointer-to-int-cast
#cgo windows LDFLAGS: -L. -lvmrp ${SRCDIR}/../windows/unicorn.a -lpthread -lm -lz

#include "gui.h"
*/
import "C"

import (
	"image"
	"image/color"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/canvas"
	"fyne.io/fyne/driver/desktop"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
)

var isDown = false
var g_game *game
var imgCache *image.RGBA

type gameRenderer struct {
	render   *canvas.Raster
	objects  []fyne.CanvasObject
	imgCache *image.RGBA
	game     *game
}

func (g *gameRenderer) MinSize() fyne.Size {
	return fyne.NewSize(g.game.width, g.game.height)
}

func (g *gameRenderer) Layout(size fyne.Size) {
	g.render.Resize(size)
}

func (g *gameRenderer) BackgroundColor() color.Color {
	return theme.BackgroundColor()
}

func (g *gameRenderer) Refresh() {
	canvas.Refresh(g.render)
}

func (g *gameRenderer) Objects() []fyne.CanvasObject {
	return g.objects
}

func (g *gameRenderer) Destroy() {
}

type game struct {
	widget.BaseWidget
	width  int
	height int
}

func (g *game) CreateRenderer() fyne.WidgetRenderer {
	renderer := &gameRenderer{game: g}
	imgCache = image.NewRGBA(image.Rect(0, 0, g.width, g.height))
	render := canvas.NewRaster(func(w, h int) image.Image {
		// fmt.Printf("draw w:%d, h:%d\n", w, h)
		return imgCache
	})
	renderer.render = render
	renderer.objects = []fyne.CanvasObject{render}

	return renderer
}

func (g *game) MouseIn(ev *desktop.MouseEvent) {
}

func (g *game) MouseOut() {
}

func (g *game) MouseMoved(ev *desktop.MouseEvent) {
	if isDown {
		C.event(C.MOUSE_MOVE, C.int(ev.Position.X), C.int(ev.Position.Y))
	}
}

func (g *game) MouseDown(ev *desktop.MouseEvent) {
	isDown = true
	C.event(C.MOUSE_DOWN, C.int(ev.Position.X), C.int(ev.Position.Y))
}

func (g *game) MouseUp(ev *desktop.MouseEvent) {
	isDown = false
	C.event(C.MOUSE_UP, C.int(ev.Position.X), C.int(ev.Position.Y))
}

//export setPixel
func setPixel(x, y C.int32_t, r, g, b C.uint8_t) {
	imgCache.SetRGBA(int(x), int(y), color.RGBA{uint8(r), uint8(g), uint8(b), 0})
}

//export refresh
func refresh() {
	g_game.Refresh()
}

func main() {
	app := app.New()
	window := app.NewWindow("vmrp")
	g_game = &game{width: 240, height: 320}
	g_game.ExtendBaseWidget(g_game)
	window.SetContent(g_game)
	window.SetFixedSize(true)
	window.CenterOnScreen()
	window.Show()

	C.init()

	app.Run()
}
