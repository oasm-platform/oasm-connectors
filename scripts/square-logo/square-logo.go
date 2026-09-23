// Command square-logo writes a square, white-background PNG for a connector
// icon: the input is downscaled so its longest edge fits `-size` and centred on
// a `-size`x`-size` white canvas. Run it on logo.png, then regenerate the
// catalog with `go run ./scripts/combine-manifest` (the logo is already within the
// 128px budget afterwards, so the aggregator leaves it verbatim).
//
// Usage: go run ./scripts/square-logo -in ports_scanner/nmap/logo.png -size 128
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"

	xdraw "golang.org/x/image/draw"
)

func main() {
	in := flag.String("in", "", "input PNG (rewritten in place)")
	size := flag.Int("size", 128, "output square edge in pixels")
	flag.Parse()
	if *in == "" {
		fmt.Fprintln(os.Stderr, "error: -in is required")
		os.Exit(1)
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		fail(err)
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		fail(err)
	}

	// Downscale the long edge onto the canvas, never upscale.
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w > *size || h > *size {
		if w >= h {
			h = max(h**size/w, 1)
			w = *size
		} else {
			w = max(w**size/h, 1)
			h = *size
		}
		scaled := image.NewRGBA(image.Rect(0, 0, w, h))
		xdraw.CatmullRom.Scale(scaled, scaled.Bounds(), src, b, draw.Over, nil)
		src, b = scaled, scaled.Bounds()
	}

	// White backdrop, then the icon centred on it: the result is square by
	// construction, so an aspect-ratio icon never renders letterboxed.
	canvas := image.NewRGBA(image.Rect(0, 0, *size, *size))
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{C: color.White}, image.Point{}, draw.Src)
	off := image.Pt((*size-b.Dx())/2, (*size-b.Dy())/2)
	draw.Draw(canvas, image.Rectangle{Min: off, Max: off.Add(b.Size())}, src, b.Min, draw.Over)

	var buf bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&buf, canvas); err != nil {
		fail(err)
	}
	if err := os.WriteFile(*in, buf.Bytes(), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %s: %dx%d canvas, icon %dx%d at %v, %d bytes\n", *in, *size, *size, b.Dx(), b.Dy(), off, buf.Len())
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
