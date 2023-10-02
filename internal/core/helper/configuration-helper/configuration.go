package helper

type Configuration struct {
	ServiceAddress     string `mapstructure:"Service__Address"`
	ServicePort        string `mapstructure:"Service__Port"`
	ServiceMode        string `mapstructure:"Service__Mode"`
	ServiceName        string `mapstructure:"Service__Name"`
	LogFile            string `mapstructure:"Service__LogFileName"`
	LogDir             string `mapstructure:"Service__LogDirectory"`
	LaunchUrl          string `mapstructure:"Service__LaunchUrl"`
	AppName            string `mapstructure:"Service__AppName"`
	Account            string `mapstructure:"Service__Account"`
	Key                string `mapstructure:"Service__Key"`
	DBConnectionString string `mapstructure:"DBConnection__ConnectionString"`
	DBName             string `mapstructure:"DBConnection__DatabaseName"`
	PageLimit          string `mapstructure:"DBConnection__PageLimit"`
	DBConnectionType   string `mapstructure:"DBConnection__Type"`
	EBConnectionString string `mapstructure:"EBConnection__ConnectionString"`
	EBConnectionTTL    string `mapstructure:"EBConnection__TTl"`
	ExternalConfigPath string `mapstructure:"external_config_path"`
	IdentityExpiry     string `mapstructure:"Service__IdentityExpiry"`
	TokenKey           string `mapstructure:"Token__Key"`
	Audience           string `mapstructure:"Token__Audience"`
	Issuer             string `mapstructure:"Token__Issuer"`
	Duration           string `mapstructure:"Token__Duration"`
	SigningAlgorithm   string `mapstructure:"Token__SigningAlgorithm"`
}
