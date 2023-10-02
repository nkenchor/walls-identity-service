package shared

import "errors"

type DeviceType int
type Channel int
type NotificationType int
type TierType int
type IntegrationType int
type IdentificationType int
type ProfileType int

const (
	Mobile DeviceType = iota
	Tablet
	Desktop
)

const (
	Sms Channel = iota
	Email
)
const (
	Instant NotificationType = iota
	Scheduled
)
const (
	BumbleBee TierType = iota
	JazzBerry
	FunkyFlamingo
	JovialJaguar
	Nebula
	WorkingBee
)
const (
	IntegrationType1 IntegrationType = iota
	IntegrationType2
)

const (
	InternationalPassport IdentificationType = iota
	BVN
	NIN
	DriversLicence
	VotersCard
)

const (
	Identity ProfileType = iota //
	Company
)

func (it IdentificationType) String() string {
	switch it {
	case InternationalPassport:
		return "International Passport"
	case BVN:
		return "Bank Verification Number"
	case NIN:
		return "National Identification Number"
	case DriversLicence:
		return "Driver's Licence"
	case VotersCard:
		return "Voter's Card"
	default:
		return "Unknown"
	}
}
func (it TierType) String() string {
	switch it {
	case BumbleBee:
		return "Bumble Bee"
	case JazzBerry:
		return "Jazz Berry"
	case FunkyFlamingo:
		return "Funky Flamingo"
	case JovialJaguar:
		return "Jovial Jaguar"
	case Nebula:
		return "Nebula"
	case WorkingBee:
		return "Working Bee"
	default:
		return "Unknown"

	}
}

func GetTierTypeFromString(tierTypeString string) (TierType, error) {
	tierTypeMap := map[string]TierType{
		"Bumble Bee":     BumbleBee,
		"Jazz Berry":     JazzBerry,
		"Funky Flamingo": FunkyFlamingo,
		"Jovial Jaguar":  JovialJaguar,
		"Nebula":         Nebula,
		"Working Bee":    WorkingBee,
	}

	tierType, found := tierTypeMap[tierTypeString]
	if !found {
		return 0, errors.New("unknown TierType")
	}

	return tierType, nil
}

func GetIdTypeFromString(idTypeString string) (IdentificationType, error) {
	idTypeMap := map[string]IdentificationType{
		"International Passport":         InternationalPassport,
		"Bank Verification Number":       BVN,
		"National Identification Number": NIN,
		"Driver's Licence":               DriversLicence,
		"Voter's Card":                   VotersCard,
	}

	idType, found := idTypeMap[idTypeString]
	if !found {
		return 0, errors.New("unknown IdType")
	}

	return idType, nil
}
