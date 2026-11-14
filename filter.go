package main

import (
	"fmt"
	"path"
	"strings"
)

// nameFilter отбирает узлы подписки по имени: если задан хотя бы один include, остаются только
// узлы, подходящие под один из них; затем отбрасываются узлы, подходящие под любой exclude.
type nameFilter struct {
	include []string
	exclude []string
}

func newNameFilter(include, exclude []string) (nameFilter, error) {
	var f nameFilter
	for _, pattern := range include {
		p, err := normalizeGlob(pattern)
		if err != nil {
			return nameFilter{}, fmt.Errorf("неверная маска --include %q: %w", pattern, err)
		}
		f.include = append(f.include, p)
	}
	for _, pattern := range exclude {
		p, err := normalizeGlob(pattern)
		if err != nil {
			return nameFilter{}, fmt.Errorf("неверная маска --exclude %q: %w", pattern, err)
		}
		f.exclude = append(f.exclude, p)
	}
	return f, nil
}

func (f nameFilter) allows(name string) bool {
	name = normalizeName(name)
	if len(f.include) > 0 && !matchesAny(f.include, name) {
		return false
	}
	return !matchesAny(f.exclude, name)
}

func matchesAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// normalizeName приводит имя к виду, в котором path.Match сравнивает без учёта регистра и
// `*`/`?` совпадают с `/`.
func normalizeName(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "/", "\x00")
}

func normalizeGlob(pattern string) (string, error) {
	p := normalizeName(pattern)
	if _, err := path.Match(p, ""); err != nil {
		return "", err
	}
	return p, nil
}
