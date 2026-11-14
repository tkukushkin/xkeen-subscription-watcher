package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

type outboundChanges struct {
	upserts  []map[string]any
	removals []string
}

type outboundAPI interface {
	addOutbound(outbound map[string]any) error
	removeOutbound(tag string) error
}

type tagFailure int

const (
	removeFailed tagFailure = iota + 1
	addFailed
)

type outboundsFileContent struct {
	Outbounds []map[string]any `json:"outbounds"`
}

// parseOutboundsFile разбирает файл подписки. nil означает, что файла нет.
func parseOutboundsFile(content []byte) ([]map[string]any, error) {
	if content == nil {
		return nil, nil
	}
	var parsed outboundsFileContent
	if err := json.Unmarshal(content, &parsed); err != nil {
		return nil, err
	}
	return parsed.Outbounds, nil
}

func marshalOutbounds(outbounds any) ([]byte, error) {
	content, err := json.MarshalIndent(map[string]any{"outbounds": outbounds}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("ошибка сериализации JSON: %w", err)
	}
	return append(content, '\n'), nil
}

func outboundTag(outbound map[string]any) string {
	tag, _ := outbound["tag"].(string)
	return tag
}

func outboundsByTag(outbounds []map[string]any) map[string]map[string]any {
	result := make(map[string]map[string]any, len(outbounds))
	for _, o := range outbounds {
		result[outboundTag(o)] = o
	}
	return result
}

// diffOutbounds сравнивает прежние и новые outbounds подписки по тегам.
func diffOutbounds(oldOutbounds, newOutbounds []map[string]any) outboundChanges {
	oldByTag := outboundsByTag(oldOutbounds)
	newByTag := outboundsByTag(newOutbounds)

	var changes outboundChanges
	for _, o := range newOutbounds {
		if old, ok := oldByTag[outboundTag(o)]; ok && reflect.DeepEqual(old, o) {
			continue
		}
		changes.upserts = append(changes.upserts, o)
	}
	for _, o := range oldOutbounds {
		if tag := outboundTag(o); newByTag[tag] == nil {
			changes.removals = append(changes.removals, tag)
		}
	}
	return changes
}

// applyChanges заменяет каждый новый или изменённый outbound парой rmo + ado, затем удаляет
// исчезнувшие. Ошибка на одном теге не останавливает обработку остальных. Возвращает теги,
// на которых случилась ошибка, и на каком шаге.
func applyChanges(api outboundAPI, changes outboundChanges) (map[string]tagFailure, error) {
	failed := make(map[string]tagFailure)
	var errs []error
	for _, o := range changes.upserts {
		tag := outboundTag(o)
		if err := api.removeOutbound(tag); err != nil {
			failed[tag] = removeFailed
			errs = append(errs, fmt.Errorf("outbound %q: %w", tag, err))
			continue
		}
		if err := api.addOutbound(o); err != nil {
			failed[tag] = addFailed
			errs = append(errs, fmt.Errorf("outbound %q: %w", tag, err))
		}
	}
	for _, tag := range changes.removals {
		if err := api.removeOutbound(tag); err != nil {
			failed[tag] = removeFailed
			errs = append(errs, fmt.Errorf("outbound %q: %w", tag, err))
		}
	}
	return failed, errors.Join(errs...)
}

// appliedOutbounds возвращает outbounds подписки, которые есть в Xray после applyChanges:
// новые версии успешных тегов, прежние версии тегов с упавшим rmo, без тегов с упавшим ado.
func appliedOutbounds(oldOutbounds, newOutbounds []map[string]any, failed map[string]tagFailure) []map[string]any {
	oldByTag := outboundsByTag(oldOutbounds)
	newByTag := outboundsByTag(newOutbounds)

	result := []map[string]any{}
	for _, o := range newOutbounds {
		tag := outboundTag(o)
		switch failed[tag] {
		case addFailed:
		case removeFailed:
			if old, ok := oldByTag[tag]; ok {
				result = append(result, old)
			}
		default:
			result = append(result, o)
		}
	}
	for _, o := range oldOutbounds {
		tag := outboundTag(o)
		if newByTag[tag] == nil && failed[tag] == removeFailed {
			result = append(result, o)
		}
	}
	return result
}
