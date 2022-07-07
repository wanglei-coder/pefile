package pe

import "github.com/pkg/errors"

var (
	ErrInvalidPESize = errors.New("not a PE file, smaller than tiny PE")
)

var (
	ErrOutsideBoundary    = errors.New("reading data outside boundary")
	ErrDamagedImportTable = errors.New(
		"damaged Import Table information. ILT and/or IAT appear to be broken")
)
