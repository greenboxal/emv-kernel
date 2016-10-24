package emv

import "time"

type Transaction struct {
	Type             int
	Date             time.Time
	Amount           int
	AdditionalAmount int
}
