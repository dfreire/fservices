package files

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Machiel/slugify"
	"github.com/labstack/echo"
)

func Upload(c *echo.Context) error {
	req := c.Request()
	req.ParseMultipartForm(16 * 1024 * 1024)

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
		dst, err := os.Create(slugifyFilename(f.Filename))
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

func slugifyFilename(filename string) string {
	extension := filepath.Ext(filename)
	name := slugify.Slugify(filename[0 : len(filename)-len(extension)])
	return strings.Join([]string{name, extension}, "")
}
