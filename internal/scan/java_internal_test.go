package scan

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestImageJavaSettings(t *testing.T) {
	t.Parallel()
	config := v1.Config{
		WorkingDir: "/app",
		Env:        []string{"JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=conf/trust.p12"},
		Entrypoint: []string{"java", "-jar", "service.jar"},
	}

	stores, evidence := imageJavaSettings(config)
	if len(evidence) == 0 {
		t.Fatal("expected JVM startup to be detected")
	}
	if !stores["app/conf/trust.p12"] {
		t.Fatalf("configured trust store was not normalized: %#v", stores)
	}
	if len(evidence) != 2 {
		t.Fatalf("got %d evidence entries, want 2", len(evidence))
	}
}

func TestDetectJDK(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, file, content string
		found               bool
		want                Component
	}{
		{
			"temurin 25",
			"opt/java/openjdk/release",
			"IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"25.0.4.1\"\nJAVA_RUNTIME_VERSION=\"25.0.4.1+1-LTS\"\n",
			true,
			Component{
				Kind:    KindJDK,
				Path:    "opt/java/openjdk/release",
				Version: "25.0.4.1",
				Status:  VersionOutdated,
				Fixed:   "25.0.5.0.2",
			},
		},
		{
			"java 8 with its build number",
			"usr/lib/jvm/java-8/jre/release",
			"JAVA_VERSION=\"1.8.0_511\"\nJAVA_RUNTIME_VERSION=\"1.8.0_511-b32\"\n",
			true,
			Component{
				Kind:    KindJDK,
				Path:    "usr/lib/jvm/java-8/jre/release",
				Version: "1.8.0_511-b32",
				Status:  VersionFixed,
			},
		},
		{"another release file", "etc/release", "NAME=Example\n", false, Component{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, found := detectJDK(test.file, []byte(test.content))
			if found != test.found || got != test.want {
				t.Errorf("detectJDK = %+v, %t; want %+v, %t", got, found, test.want, test.found)
			}
		})
	}
}
