package web

import "embed"

//go:embed templates/*.tmpl static/*
var assets embed.FS
