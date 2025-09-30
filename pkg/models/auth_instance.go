package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

type AuthInstance struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	DomainCode string    `gorm:"uniqueIndex;not null;size:255" json:"domain_code"`
	Config     JSONMap   `gorm:"type:json;not null" json:"config"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type JSONMap map[string]interface{}

func (j JSONMap) Value() (driver.Value, error) {
	return json.Marshal(j)
}

func (j *JSONMap) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, j)
}

func (AuthInstance) TableName() string {
	return "auth_instances"
}
