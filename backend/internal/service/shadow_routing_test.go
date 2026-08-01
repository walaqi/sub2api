package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultSparkShadowModelMapping(t *testing.T) {
	mapping := defaultSparkShadowModelMapping()

	// fork 的 codexModelMap 含 spark base + 4 个 effort 变体（fork 提交 3734abed4
	// 「支持 gpt-5.3-codex-spark」）。defaultSparkShadowModelMapping 数据驱动地把
	// 全部 spark 变体纳入影子白名单，故为 5 条恒等映射（非 upstream 假设的 1 条）。
	require.Len(t, mapping, 5, "spark 白名单含 base + 4 个 effort 变体")
	for _, m := range []string{
		"gpt-5.3-codex-spark",
		"gpt-5.3-codex-spark-low",
		"gpt-5.3-codex-spark-medium",
		"gpt-5.3-codex-spark-high",
		"gpt-5.3-codex-spark-xhigh",
	} {
		require.Equal(t, m, mapping[m], "恒等映射：变体映射到自身")
	}
}

func TestSparkModelVariantsDerivedFromAliases(t *testing.T) {
	got := sparkModelVariants()
	require.ElementsMatch(t, []string{
		"gpt-5.3-codex-spark",
		"gpt-5.3-codex-spark-low",
		"gpt-5.3-codex-spark-medium",
		"gpt-5.3-codex-spark-high",
		"gpt-5.3-codex-spark-xhigh",
	}, got, "fork codexModelMap 含 spark base + 4 个 effort 变体，全部派生进影子白名单")
}
