package utils

import "testing"

func TestJoinNonEmpty(t *testing.T) {
	tests := []struct {
		elems []string
		sep   string
		want  string
	}{
		{[]string{"a", "b", "", "c"}, "-", "a-b-c"},
		{[]string{"", "", ""}, ",", ""},
		{[]string{"x"}, "|", "x"},
		{[]string{}, ";", ""},
	}

	for _, tt := range tests {
		got := JoinNonEmpty(tt.sep, tt.elems...)
		if got != tt.want {
			t.Errorf("JoinNonEmpty(%v, %q) = %q; want %q", tt.elems, tt.sep, got, tt.want)
		}
	}
}
