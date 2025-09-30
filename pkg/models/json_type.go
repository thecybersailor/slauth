package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type JSON json.RawMessage

func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New(fmt.Sprint("Failed to unmarshal JSON value:", value))
	}

	result := json.RawMessage{}
	err := json.Unmarshal(bytes, &result)
	*j = JSON(result)
	return err
}

func (j JSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return json.RawMessage(j).MarshalJSON()
}

func (JSON) GormDataType() string {
	return "json"
}

func (JSON) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	
	switch db.Dialector.Name() {
	case "mysql":
		return "JSON"
	case "postgres":
		return "JSONB"
	case "sqlite":
		return "JSON"
	default:
		return "JSON"
	}
}
