package utils

import (
	"fmt"

	"github.com/AlchemillaHQ/simple-turn/internal/config"
	"github.com/common-nighthawk/go-figure"
)

func PrintAsciiArt() {
	figure.NewFigure("SimpleTurn", "doom", true).Print()
	fmt.Println("\t\t\t\t\t\tVersion: ", config.Version)
}
