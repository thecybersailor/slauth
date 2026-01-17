package services

import (
	"time"

	"gorm.io/gorm"
)

// GetDatabaseNow returns the current UTC time from the database
// This ensures consistent time across all operations and avoids timezone issues
func GetDatabaseNow(db *gorm.DB) time.Time {
	var now time.Time
	dialect := db.Name()

	switch dialect {
	case "postgres":
		db.Raw("SELECT CURRENT_TIMESTAMP AT TIME ZONE 'UTC'").Scan(&now)
	case "mysql":
		db.Raw("SELECT UTC_TIMESTAMP()").Scan(&now)
	case "sqlite":
		var nowStr string
		db.Raw("SELECT datetime('now')").Scan(&nowStr)
		now, _ = time.Parse("2006-01-02 15:04:05", nowStr)
	default:
		db.Raw("SELECT CURRENT_TIMESTAMP").Scan(&now)
	}

	return now
}

// CalculateTimeDifference calculates the time difference in seconds between database now (UTC) and a given time
// This is done entirely in the database to avoid timezone conversion issues
func CalculateTimeDifference(db *gorm.DB, fromTime time.Time) float64 {
	var diffSeconds float64
	dialect := db.Name()

	// Convert fromTime to UTC to ensure consistent comparison
	fromTimeUTC := fromTime.UTC()

	switch dialect {
	case "postgres":
		db.Raw("SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP AT TIME ZONE 'UTC' - ?))", fromTimeUTC).Scan(&diffSeconds)
	case "mysql":
		db.Raw("SELECT TIMESTAMPDIFF(SECOND, ?, UTC_TIMESTAMP())", fromTimeUTC).Scan(&diffSeconds)
	case "sqlite":
		db.Raw("SELECT (julianday('now') - julianday(?)) * 86400", fromTimeUTC).Scan(&diffSeconds)
	default:
		db.Raw("SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - ?))", fromTimeUTC).Scan(&diffSeconds)
	}

	return diffSeconds
}
