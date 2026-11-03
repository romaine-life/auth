package client

import (
	"context"
	"encoding/json"
	"errors"
)

func SetMachineGrants(ctx context.Context, subject string, apps json.RawMessage) error {
	if !json.Valid(apps) {
		return errors.New("grants must be JSON")
	}
	token, err := ReadHumanToken(ConfigDir())
	if err != nil {
		return err
	}
	var result any
	return post(ctx, BaseURL+"/api/admin/machines/grants", map[string]any{"subject": subject, "apps": apps}, token, &result)
}
