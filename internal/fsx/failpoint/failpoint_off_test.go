//go:build !failpoints

package failpoint_test

import (
	"testing"

	"github.com/precinto/precinto/internal/fsx/failpoint"
)

func TestCompiledOut(t *testing.T) {
	if failpoint.Enabled() || failpoint.Hit("fsx.write") != nil {
		t.Fatal("failpoints must be no-ops without -tags failpoints")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Set must panic without -tags failpoints")
		}
	}()
	failpoint.Set("fsx.write")
}
