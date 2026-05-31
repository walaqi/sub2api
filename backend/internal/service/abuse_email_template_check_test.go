//go:build unit

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAbuseDisabledEventHasOfficialTemplate(t *testing.T) {
	for _, locale := range []string{notificationEmailDefaultLocale, notificationEmailLocaleChinese} {
		tmpl, ok := notificationEmailOfficialTemplates[NotificationEmailEventAbuseAccountDisabled][locale]
		require.True(t, ok, "missing official template for locale %s", locale)
		require.NotEmpty(t, tmpl.Subject)
		require.NotEmpty(t, tmpl.HTML)
	}
	// event must be in the ordered list so it appears in the admin editor
	found := false
	for _, e := range notificationEmailEventOrder {
		if e == NotificationEmailEventAbuseAccountDisabled {
			found = true
		}
	}
	require.True(t, found, "abuse_disabled event not registered in notificationEmailEventOrder")
	// and must have an event definition
	_, ok := notificationEmailEventDefinitions[NotificationEmailEventAbuseAccountDisabled]
	require.True(t, ok, "abuse_disabled event missing definition")
}
