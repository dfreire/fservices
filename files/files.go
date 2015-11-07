package files

import (
	"io"
	"os"

	"github.com/labstack/echo"
)

func Upload(c *echo.Context) error {
	req := c.Request()
	req.ParseMultipartForm(16 << 20) // Max memory 16 MiB

	// Read files
	files := req.MultipartForm.File["files"]
	for _, f := range files {
		// Source file
		src, err := f.Open()
		if err != nil {
			return err
		}
		defer src.Close()

		// Destination file
		dst, err := os.Create(f.Filename)
		if err != nil {
			return err
		}
		defer dst.Close()

		if _, err = io.Copy(dst, src); err != nil {
			return err
		}
	}
	return nil
}
