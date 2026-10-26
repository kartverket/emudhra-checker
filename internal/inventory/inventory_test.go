package inventory_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kartverket/emudhra-checker/internal/inventory"
)

func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return filename
}

func TestRead(t *testing.T) {
	t.Parallel()

	t.Run("quoted fields, header and kind column", func(t *testing.T) {
		t.Parallel()
		filename := writeTestFile(t, "images.csv", "namespace,application,image,kind\n"+
			"# comment\n"+
			"\"team,one\",service,ghcr.io/org/app:v1\n"+
			"team,nightly,ghcr.io/org/job:v1, MyCustomJob \n")

		targets, err := inventory.Read(nil, []string{filename})
		if err != nil {
			t.Fatal(err)
		}
		want := []inventory.ImageTarget{
			{Cluster: "images", Namespace: "team,one", Application: "service", Image: "ghcr.io/org/app:v1"},
			{
				Cluster:     "images",
				Namespace:   "team",
				Kind:        "MyCustomJob",
				Application: "nightly",
				Image:       "ghcr.io/org/job:v1",
			},
		}
		if len(targets) != len(want) || targets[0] != want[0] || targets[1] != want[1] {
			t.Fatalf("inventory.Read = %#v, want %#v", targets, want)
		}
	})

	t.Run("one cluster per file, duplicates removed", func(t *testing.T) {
		t.Parallel()
		row := "\"ns\",\"app\",\"ghcr.io/org/app:v1\"\n"
		files := []string{
			writeTestFile(t, "cluster2.txt", row+row),
			writeTestFile(t, "cluster1.txt", row),
		}

		targets, err := inventory.Read([]string{"nginx"}, files)
		if err != nil {
			t.Fatal(err)
		}
		if len(targets) != 3 || targets[0].Cluster != "" ||
			targets[1].Cluster != "cluster2" || targets[2].Cluster != "cluster1" {
			t.Fatalf("want one target per cluster in input order, got %#v", targets)
		}
	})

	t.Run("missing column reports the line", func(t *testing.T) {
		t.Parallel()
		filename := writeTestFile(t, "bad.csv", "ns,app,image\nns,app\n")
		_, err := inventory.Read(nil, []string{filename})
		if err == nil {
			t.Fatal("expected an error for a row with two columns")
		}
		if got, want := err.Error(), filename+":2: expected at least 3 CSV columns (namespace, application, image)"; got != want {
			t.Fatalf("error = %q, want %q", got, want)
		}
	})
}
