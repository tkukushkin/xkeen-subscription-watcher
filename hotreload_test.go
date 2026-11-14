package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ob(tag, host string) map[string]any {
	return map[string]any{
		"tag":      tag,
		"protocol": "freedom",
		"settings": map[string]any{"redirect": host},
	}
}

func obs(outbounds ...map[string]any) []map[string]any {
	return outbounds
}

func upsertTags(changes outboundChanges) []string {
	tags := []string{}
	for _, o := range changes.upserts {
		tags = append(tags, outboundTag(o))
	}
	return tags
}

func removalTags(changes outboundChanges) []string {
	return append([]string{}, changes.removals...)
}

func TestParseOutboundsFile(t *testing.T) {
	got, err := parseOutboundsFile([]byte(`{"outbounds": [{"tag": "a", "protocol": "freedom"}]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertDeepEqual(t, got, obs(map[string]any{"tag": "a", "protocol": "freedom"}))

	got, err = parseOutboundsFile(nil)
	if err != nil || got != nil {
		t.Errorf("nil content: got %v, %v", got, err)
	}

	if _, err := parseOutboundsFile([]byte("{oops")); err == nil {
		t.Error("expected error for invalid content")
	}
}

func TestDiffWithoutOldFile(t *testing.T) {
	changes := diffOutbounds(nil, obs(ob("a", "h1"), ob("b", "h1")))
	assertDeepEqual(t, upsertTags(changes), []string{"a", "b"})
	assertDeepEqual(t, removalTags(changes), []string{})
	assertDeepEqual(t, changes.upserts[0], ob("a", "h1"))
}

func TestDiffDetectsChangedAddedRemoved(t *testing.T) {
	changes := diffOutbounds(
		obs(ob("a", "h1"), ob("b", "h1"), ob("c", "h1")),
		obs(ob("a", "h1"), ob("b", "h2"), ob("d", "h1")),
	)
	assertDeepEqual(t, upsertTags(changes), []string{"b", "d"})
	assertDeepEqual(t, removalTags(changes), []string{"c"})
	assertDeepEqual(t, changes.upserts[0], ob("b", "h2"))
	assertDeepEqual(t, changes.upserts[1], ob("d", "h1"))
}

func TestDiffUnchanged(t *testing.T) {
	changes := diffOutbounds(obs(ob("a", "h1"), ob("b", "h1")), obs(ob("a", "h1"), ob("b", "h1")))
	assertDeepEqual(t, upsertTags(changes), []string{})
	assertDeepEqual(t, removalTags(changes), []string{})
}

func TestDiffNewFileWithoutOutbounds(t *testing.T) {
	changes := diffOutbounds(obs(ob("a", "h1"), ob("b", "h1")), nil)
	assertDeepEqual(t, upsertTags(changes), []string{})
	assertDeepEqual(t, removalTags(changes), []string{"a", "b"})
}

type fakeAPI struct {
	calls      []string
	failAdd    map[string]bool
	failRemove map[string]bool
}

func (f *fakeAPI) addOutbound(outbound map[string]any) error {
	tag := outboundTag(outbound)
	f.calls = append(f.calls, "ado "+tag)
	if f.failAdd[tag] {
		return errors.New("add failed")
	}
	return nil
}

func (f *fakeAPI) removeOutbound(tag string) error {
	f.calls = append(f.calls, "rmo "+tag)
	if f.failRemove[tag] {
		return errors.New("remove failed")
	}
	return nil
}

func TestApplyPairsRemoveAndAddPerTag(t *testing.T) {
	api := &fakeAPI{}
	changes := outboundChanges{upserts: obs(ob("a", "h1"), ob("b", "h1")), removals: []string{"c"}}

	failed, err := applyChanges(api, changes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertDeepEqual(t, api.calls, []string{"rmo a", "ado a", "rmo b", "ado b", "rmo c"})
	if len(failed) != 0 {
		t.Errorf("expected no failures, got %v", failed)
	}
}

func TestApplyContinuesAfterError(t *testing.T) {
	api := &fakeAPI{failAdd: map[string]bool{"a": true}}
	changes := outboundChanges{upserts: obs(ob("a", "h1"), ob("b", "h1")), removals: []string{"c"}}

	failed, err := applyChanges(api, changes)
	if err == nil {
		t.Fatal("expected error")
	}
	assertDeepEqual(t, api.calls, []string{"rmo a", "ado a", "rmo b", "ado b", "rmo c"})
	assertDeepEqual(t, failed, map[string]tagFailure{"a": addFailed})
	if !strings.Contains(err.Error(), `outbound "a"`) {
		t.Errorf("error should mention outbound a: %v", err)
	}
	if strings.Contains(err.Error(), `outbound "b"`) {
		t.Errorf("error should not mention outbound b: %v", err)
	}
}

func TestApplySkipsAddWhenRemoveFails(t *testing.T) {
	api := &fakeAPI{failRemove: map[string]bool{"a": true, "c": true}}
	changes := outboundChanges{upserts: obs(ob("a", "h1")), removals: []string{"c"}}

	failed, err := applyChanges(api, changes)
	if err == nil {
		t.Fatal("expected error")
	}
	assertDeepEqual(t, api.calls, []string{"rmo a", "rmo c"})
	assertDeepEqual(t, failed, map[string]tagFailure{"a": removeFailed, "c": removeFailed})
}

func newTestUpdate(t *testing.T, oldOutbounds, newOutbounds []map[string]any) *pendingUpdate {
	t.Helper()
	oldContent, err := marshalOutbounds(oldOutbounds)
	if err != nil {
		t.Fatal(err)
	}
	newContent, err := marshalOutbounds(newOutbounds)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "04_outbounds.s.json")
	if err := os.WriteFile(path, oldContent, 0644); err != nil {
		t.Fatal(err)
	}
	return &pendingUpdate{sub: subscription{tag: "s"}, path: path, oldContent: oldContent, newContent: newContent}
}

func marshalled(t *testing.T, outbounds ...map[string]any) []byte {
	t.Helper()
	content, err := marshalOutbounds(append([]map[string]any{}, outbounds...))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestApplyUpdateWritesNewContentOnSuccess(t *testing.T) {
	update := newTestUpdate(t, obs(ob("a", "h1")), obs(ob("a", "h2")))

	if err := applyUpdate(&fakeAPI{}, update); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFileEquals(t, update.path, update.newContent)
}

func TestApplyUpdateKeepsFileWhenNothingApplied(t *testing.T) {
	update := newTestUpdate(t, obs(ob("a", "h1"), ob("b", "h1")), obs(ob("a", "h2"), ob("c", "h1")))
	before, err := os.Stat(update.path)
	if err != nil {
		t.Fatal(err)
	}

	api := &fakeAPI{failRemove: map[string]bool{"a": true, "b": true, "c": true}}
	if err := applyUpdate(api, update); err == nil {
		t.Fatal("expected error")
	}
	after, err := os.Stat(update.path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("file should not be rewritten when nothing was applied")
	}
	assertFileEquals(t, update.path, update.oldContent)
}

func TestApplyUpdateDropsTagWhenAddFails(t *testing.T) {
	update := newTestUpdate(t, obs(ob("a", "h1")), obs(ob("a", "h2")))

	api := &fakeAPI{failAdd: map[string]bool{"a": true}}
	if err := applyUpdate(api, update); err == nil {
		t.Fatal("expected error")
	}
	assertFileEquals(t, update.path, marshalled(t))
}

func TestApplyUpdateWritesAppliedStateOnMixedFailures(t *testing.T) {
	update := newTestUpdate(t,
		obs(ob("a", "h1"), ob("b", "h1"), ob("c", "h1")),
		obs(ob("a", "h2"), ob("b", "h2"), ob("d", "h1")),
	)

	api := &fakeAPI{failAdd: map[string]bool{"b": true}, failRemove: map[string]bool{"c": true}}
	if err := applyUpdate(api, update); err == nil {
		t.Fatal("expected error")
	}
	assertFileEquals(t, update.path, marshalled(t, ob("a", "h2"), ob("d", "h1"), ob("c", "h1")))
}

func TestApplyUpdateWritesAtomically(t *testing.T) {
	update := newTestUpdate(t, obs(ob("a", "h1"), ob("b", "h1")), obs(ob("a", "h2"), ob("b", "h2")))
	link := filepath.Join(t.TempDir(), "old-link")
	if err := os.Link(update.path, link); err != nil {
		t.Fatal(err)
	}

	api := &fakeAPI{failAdd: map[string]bool{"b": true}}
	if err := applyUpdate(api, update); err == nil {
		t.Fatal("expected error")
	}
	assertFileEquals(t, update.path, marshalled(t, ob("a", "h2")))
	assertFileEquals(t, link, update.oldContent)
}

func TestAppliedOutboundsWithoutFailuresIsNew(t *testing.T) {
	newOutbounds := obs(ob("a", "h1"), ob("b", "h2"))
	got := appliedOutbounds(obs(ob("a", "h1"), ob("c", "h1")), newOutbounds, nil)
	assertDeepEqual(t, got, newOutbounds)
}

func TestAppliedOutboundsReflectsFailures(t *testing.T) {
	oldOutbounds := obs(ob("a", "h1"), ob("b", "h1"), ob("c", "h1"), ob("e", "h1"), ob("f", "h1"))
	newOutbounds := obs(ob("a", "h1"), ob("b", "h2"), ob("d", "h1"), ob("e", "h2"), ob("g", "h1"))
	failed := map[string]tagFailure{
		"b": addFailed,    // изменённый, rmo прошёл, ado упал → тега нет
		"e": removeFailed, // изменённый, rmo упал → прежняя версия
		"g": removeFailed, // новый, rmo упал → тега нет
		"c": removeFailed, // исчезнувший, rmo упал → прежняя версия в конце
	}

	got := appliedOutbounds(oldOutbounds, newOutbounds, failed)
	assertDeepEqual(t, got, obs(ob("a", "h1"), ob("d", "h1"), ob("e", "h1"), ob("c", "h1")))
}

func TestAppliedOutboundsEmptyIsNotNil(t *testing.T) {
	got := appliedOutbounds(nil, obs(ob("a", "h1")), map[string]tagFailure{"a": addFailed})
	if got == nil || len(got) != 0 {
		t.Errorf("expected empty non-nil slice, got %#v", got)
	}
}
